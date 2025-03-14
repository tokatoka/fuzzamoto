*Work in progress*

# Fuzzamoto: Holistic Fuzzing for Bitcoin Protocol Implementations

Fuzzamoto provides a framework for coverage-guided fuzzing of Bitcoin full node
implementations in a holistic fashion. Instead of the common in-process
`LLVMFuzzerTestOneInput` style tests, testing is performed through external
facing interfaces, such as P2P, RPC, etc ([`Bitcoin
Core`](https://github.com/bitcoin/bitcoin) contributors can think of it as
"Functional Fuzz Tests").

## Design

Snapshot fuzzing lies at the core of Fuzzamoto, to allow for deterministic and
performant fuzzing of one or more full node instances at once. Currently,
only support for snapshot fuzzing with afl++'s [`Nyx`](https://nyx-fuzz.com/) mode
is implemented but future integration with other snapshot fuzzing tools is
possible (e.g. full-system
[`libafl_qemu`](https://github.com/AFLplusplus/LibAFL)).

The rough architecture when fuzzing with fuzzamoto looks as follows:

```
                          Report bug
                               ^
                               |
                              Yes
                               |
         -------------------> Bug? -------------------
         |                                            |
---------|------------ Nyx VM ----------------------  |
|        |                                         |  |
|  -------------                     ------------- |  |
|  | Fuzzamoto | <---p2p/rpc/...---> | Full Node | |  No
|  -------------                     ------------- |  |
|        ^                                         |  |
---------|------------------------------------------  |
         |                                            |
         |                                            |
 Generate testcase < ----------------------------------
```

At the moment, only support for Bitcoin Core as target application is
implemented but the existing abstractions allow for integration with other
projects as well (e.g. [`btcd`](https://github.com/btcsuite/btcd),
[`libbitcoin`](https://github.com/libbitcoin/libbitcoin)).

The full node software under test is extended with a crash handler that reports
application aborts to Nyx (See
[`nyx-crash-handler.c`](fuzzamoto-nyx-sys/src/nyx-crash-handler.c)) and the
harness includes a nyx agent that deals with setup and snapshot creation (See
[`nyx-agent.c`](fuzzamoto-nyx-sys/src/nyx-agent.c)).

## Usage

Actual fuzzing (i.e. input generation) can currently only be done on bare metal
x86-64 systems (limitiation of Nyx). See the [Dockerfile](Dockerfile) for an
example setup.

Example: fuzzing the http server of Bitcoin Core:

```
$ docker build -t fuzzamoto .
$ docker run --privileged -it fuzzamoto bash
root@...# mkdir /tmp/in && echo "AAA" > /tmp/in/A
root@...# afl-fuzz -X -i /tmp/in -o /tmp/out -- /tmp/fuzzamoto_scenario-http-server
```

### Multi-core campaigns

Running a multi-core campaign can be done with
[`AFL_Runner`](https://github.com/0xricksanchez/AFL_Runner) (installed in the
[Dockerfile](Dockerfile)).

Example: fuzzing the http server of Bitcoin Core with 16 cores:

```
root@...# aflr run --nyx-mode --target /tmp/fuzzamoto_scenario-http-server/ \
    --input-dir /tmp/http_in/ --output-dir /tmp/http_out/ \
    --runners 16
```

### Reproducing testcases

Crashing inputs or other solutions can be reproduced on any architecture with
something similar to the following:

```
$ # Rebuild fuzzamoto without nyx feature
$ cargo build --release --features inherit_stdout --workspace
$ cat ./testcase.dat | ./target/release/fuzzamoto_scenario-http-server ./bitcoind
```

`--features inherit_stdout` is used to inherit stdout from the target
application, such that any logs, stack traces, etc. are printed to the
terminal.

### Custom target patches

Certain targets require custom patches for effective fuzzing and testcase
reproduction. These can be found in the [`target-patches`](target-patches)
directory.

Maintaining external patches should be avoided if possible, as it has several
downsides:

* They might become outdated and require rebase
* They might not apply to a PR we would like to fuzz, in which case the patch
  needs to be adjusted just for the PR
* Testcases might not reproduce without the patches and it is on the user to
  make sure all patches were applied correctly

If a patch is necessary, then landing it in the target application is preferred
but in the case of a fuzz blocker (e.g. checksum check in the target) the best
solution is to make the harness/test produce valid inputs (if possible).

Current patches:

- `bitcoin-core-rng.patch`: Attempts to make Bitcoin Core's RNG deterministic
