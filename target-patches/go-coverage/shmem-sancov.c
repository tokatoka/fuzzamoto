// Fuzzamoto-compatible Go coverage instrumentation.
//
// This file provides sanitizer coverage callback implementations for Go
// programs built with libfuzzer instrumentation support. It integrates with the
// Fuzzamoto fuzzing framework by connecting to the same shared memory segment
// used by the Fuzzamoto Nyx agent.
//
// Usage:
// 1. Link this file into Go programs built with `-gcflags=all=-d=libfuzzer`
// 2. The Fuzzamoto agent sets __AFL_SHM_ID and AFL_MAP_SIZE environment
//    variables
// 3. Call sancov_copy_coverage_to_shmem() from Go to transfer coverage data
//    from the 8-bit counters to the shared memory segment
//
// The shared memory layout matches Fuzzamoto's expectations, allowing
// coverage-guided fuzzing of Go programs.

#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ipc.h>
#include <sys/shm.h>

#ifdef __cplusplus
extern "C" {
#endif

static uint8_t *__coverage_map = NULL;
static size_t __coverage_map_size = 0;
static pthread_mutex_t __coverage_mutex = PTHREAD_MUTEX_INITIALIZER;
static int __coverage_initialized = 0;

static uint8_t *__counters_start = NULL;
static uint8_t *__counters_end = NULL;

static int __init_coverage_map(void) {
  if (__coverage_initialized) {
    return 1;
  }

  const char *shm_id_str = getenv("__AFL_SHM_ID");
  if (!shm_id_str) {
    printf("Warning: __AFL_SHM_ID not set, coverage tracking disabled\n");
    return 0;
  }

  int shm_id = atoi(shm_id_str);
  if (shm_id < 0) {
    printf("Warning: Invalid __AFL_SHM_ID value: %s\n", shm_id_str);
    return 0;
  }

  __coverage_map = (uint8_t *)shmat(shm_id, NULL, 0);
  if (__coverage_map == (void *)-1) {
    printf("Warning: Failed to attach to shared memory segment %d\n", shm_id);
    __coverage_map = NULL;
    return 0;
  }

  const char *map_size_str = getenv("AFL_MAP_SIZE");
  if (map_size_str) {
    __coverage_map_size = (size_t)atoi(map_size_str);
  } else {
    __coverage_map_size = 65536;
  }

  printf("Coverage map initialized: %p (size: %zu)\n", __coverage_map,
         __coverage_map_size);
  __coverage_initialized = 1;
  return 1;
}

__attribute__((weak)) void sancov_copy_coverage_to_shmem(void) {
  if (!__coverage_map || !__counters_start || !__counters_end) {
    return;
  }

  pthread_mutex_lock(&__coverage_mutex);

  size_t counters_size = __counters_end - __counters_start;
  size_t copy_size =
      counters_size < __coverage_map_size ? counters_size : __coverage_map_size;

  memcpy(__coverage_map, __counters_start, copy_size);

  pthread_mutex_unlock(&__coverage_mutex);
}

__attribute__((weak)) void __sanitizer_cov_pcs_init(const uintptr_t *pcs_beg,
                                                    const uintptr_t *pcs_end) {}

__attribute__((weak)) void __sanitizer_cov_8bit_counters_init(char *start,
                                                              char *end) {
  const char *dump_map_size_str = getenv("AFL_DUMP_MAP_SIZE");
  if (dump_map_size_str) {
    printf("%d\n", (int)(end - start));
    exit(0);
  }

  __init_coverage_map();
  __counters_start = (uint8_t *)start;
  __counters_end = (uint8_t *)end;

  if (__coverage_map && __counters_start && __counters_end) {
    size_t counters_size = __counters_end - __counters_start;
    printf("Mapping %zu counters to coverage map\n", counters_size);

    if (counters_size > __coverage_map_size) {
      printf("Warning: Counter size (%zu) exceeds map size (%zu)\n",
             counters_size, __coverage_map_size);
    }
  }
}

__attribute__((weak)) void __sanitizer_cov_trace_cmp1(uint8_t arg1,
                                                      uint8_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_cmp2(uint16_t arg1,
                                                      uint16_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_cmp4(uint32_t arg1,
                                                      uint32_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_cmp8(uint64_t arg1,
                                                      uint64_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_const_cmp1(uint8_t arg1,
                                                            uint8_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_const_cmp2(uint16_t arg1,
                                                            uint16_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_const_cmp4(uint32_t arg1,
                                                            uint32_t arg2) {}

__attribute__((weak)) void __sanitizer_cov_trace_const_cmp8(uint64_t arg1,
                                                            uint64_t arg2) {}

__attribute__((weak)) void __sanitizer_weak_hook_strcmp(const char *s1,
                                                        const char *s2) {}

#ifdef __cplusplus
}
#endif
