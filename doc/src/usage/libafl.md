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

**More instructions will follow soon, see the inline documentation in
Dockerfile.libafl for now.**
