# Snapshot Fuzzing

To achieve deterministic and performant fuzzing of one or more full node
instances, snapshot fuzzing is used. With snapshot fuzzing, testcases are
executed inside a special virtual machine that has the ability to take a
snapshot of itself (CPU registers, memory, disk, other devices, ...) and also
to reset itself quickly to that snapshot.


The rough architecture when fuzzing with fuzzamoto looks as follows:

```
                       Report bug                              
                           ▲                                   
                           │                                   
                           │                                   
                          Yes                                  
                           │                                   
                           │                                   
       ┌─────────────────►Bug?───────────────────────────────┐ 
       │                                                     │ 
       │                                                     │ 
       │                                                     │ 
┌──────┼──────────── Virtural Machine ──────────────────┐    │ 
│      │                                                │    │ 
│ ┌────┼─────┐                            ┌───────────┐ │    │ 
│ │ Scenario │◄───────p2p/rpc/...────────►│ Full Node │ │    No
│ └────▲─────┘                            └───────────┘ │    │ 
│      │                                                │    │ 
└──────┼────────────────────────────────────────────────┘    │ 
       │                                                     │ 
       │                                                     │ 
       │                                                     │ 
       └─────────Generate/Mutate testcase◄───────────────────┘ 
```

Inside the VM, a [scenario](./scenarios.md) runs that controls snapshot
creation and receives inputs from the fuzzer to execute against the target(s).
If a bug is detected, the scenario reports it to the fuzzer. If no crash is
detected and the scenario finishes the execution of a testcase, it tells the
fuzzer to reset the VM and provide another testcase.

## Backends

Currently, snapshot fuzzing support is only implemented for
[`Nyx`](https://nyx-fuzz.com) but other backends could also be supported in the
future.

The
[`fuzzamoto-nyx-sys`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-nyx-sys)
crate provides rust bindings to a nyx agent implementation written in C. The
agent provides the interface for scenarios to communicate with the fuzzer
through the Nyx hypercall API. The agent provides the following functionality:

* Taking a VM snapshot & receiving the next input from the fuzzer
* Reporting a crash to the fuzzer
* Resetting the VM to the snapshot
* Instructing the fuzzer to ignore the current testcase
* Dumping files to the host machine

The crate also comes with a `LD_PRELOAD`able crash handler that reports
application aborts directly to Nyx (See
[`nyx-crash-handler.c`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-nyx-sys/src/nyx-crash-handler.c)).

### Alternative Backends

In the future, using
[`libafl_qemu`](https://github.com/AFLplusplus/LibAFL/tree/main/libafl_qemu)
and its full system capabilities would enable fuzzing on and of more
architectures (Nyx only supports x86 at this time) as well enable fuzzing on
non-bare metal hardware.

## Coverage Feedback

Coverage data is collected using compile time instrumentation and communicated
to the fuzzer using Nyx's compile-time instrumentation mode. Currently, only
AFL++ coverage instrumentation is supported, which necessitates that targets
are build with `afl-clang-{fast,lto}`.

Upon initialization, the Nyx agent creates a shared memory region large enough
to fit the target's coverage map. The size of the map is previously determined
by executing the target binary with the `AFL_DUMP_MAP_SIZE=1` environment
variable (see
[`fuzzamoto-nyx-sys/build.rs`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-nyx-sys/build.rs)).
The agent then sets `__AFL_SHM_ID` and `AFL_MAP_SIZE` environment variables
(recognized by AFL++'s instrumentation) to the shared memory region's id and
size, respectively. It also informs Nyx of the address of the shared region,
which in turn is communicated to the fuzzer for feedback evaluation. Once the
target is executed, it writes the coverage data to the shared memory region.
