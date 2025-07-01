# Fuzzing with fuzzamoto-libafl

*Make sure to understand the [system requirements](./requirements.md) before
running fuzzing campaigns.*

---

[`fuzzamoto-libafl`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-libafl)
is a LibAFL based fuzzer for Fuzzamoto operating on the fuzzamoto
[`intermediate representation`](../design/ir.md). This fuzzer exclusively
operates on the [IR
scenario](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-scenarios/bin/ir.rs).

The
[Dockerfile.libafl](https://github.com/dergoegge/fuzzamoto/blob/master/Dockerfile.libafl)
at the root of the repository contains an example setup for running fuzzamoto
fuzzing campaigns with libafl.

Build the container image:

```
docker build -f Dockerfile.libafl -t fuzzamoto-libafl .
```

And then create a new container from it (mounting the current directory to
`/fuzzamoto`):

```
docker run --privileged -it -v $PWD:/fuzzamoto fuzzamoto-libafl bash
```

`--privileged` is required to enable the use of kvm by Nyx.

Inside the container, build the fuzzer and all scenarios:

```
cd /fuzzamoto
BITCOIND_PATH=/bitcoin/build_fuzz/bin/bitcoind cargo build --workspace --release --features fuzz
```

Then, build the crash handler and initialize the nyx share dir:

```
# Build the crash handler
clang-19 -fPIC -DENABLE_NYX -D_GNU_SOURCE -DNO_PT_NYX \
    ./fuzzamoto-nyx-sys/src/nyx-crash-handler.c -ldl -I. -shared -o libnyx_crash_handler.so
# Initialize the nyx share dir
./target/release/fuzzamoto-cli init --sharedir /tmp/fuzzamoto_scenario-ir \
    --crash-handler /fuzzamoto/libnyx_crash_handler.so \
    --bitcoind /bitcoin/build_fuzz/bin/bitcoind \
    --scenario ./target/release/scenario-ir
```

The fuzzer uses shared memory to communicate between its instances, you'll
likely need to increase the size of `/dev/shm`:

```
# 50% is likely overkill
mount -o remount,size=50% /dev/shm
```

Then, run the fuzzer:

```
mkdir /tmp/in
./target/release/fuzzamoto-libafl
    --input /tmp/in/ --output /tmp/out/ \
    --share /tmp/fuzzamoto_scenario-ir/ \
    --cores 0-15 # 16 cores, adjust for your system
```
