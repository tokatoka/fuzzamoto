# Scenarios

Scenarios are a core concept in Fuzzamoto. They are fuzzing harnesses,
responsible for snapshot state setup, controlling fuzz input execution and
reporting results back to the fuzzer.

Each scenario needs to implement two functions:

* Scenario creation and snapshot state setup. This is where target full node
  processes are spawned and brought into the desired state for the fuzzing
  campaign.
* Testcase execution. This is where a fuzz input is executed in the context of
  the previously created state.

Each scenario is implemented to run as a standalone process inside the VM. A
convience macro `fuzzamoto_main` exists to implement the `main` function for
scenarios, which includes the necessary glue all scenarios need.

All scenarios are implemented in the
[`fuzzamoto-scenarios`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-scenarios)
crate. For example:

* [`HttpServerScenario`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-scenarios/bin/http_server.rs):
  tests Bitcoin Core's http server. It receives raw bytes from the fuzzer and
  parses them into a sequence of operations (using
  [`Arbitrary`](https://github.com/rust-fuzz/arbitrary)) to be performed on the
  server.
* [`RpcScenario`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-scenarios/bin/rpc_generic.rs):
  generic scenario for testing Bitcoin Core's RPC interface. It receives a
  sequence of RPC calls (using
  [`Arbitrary`](https://github.com/rust-fuzz/arbitrary)) and executes them
  against the target.
* [`IrScenario`](https://github.com/dergoegge/fuzzamoto/tree/master/fuzzamoto-scenarios/bin/ir.rs):
  generic scenario for testing Bitcoin full nodes through the p2p interface.
  Primarily meant to be fuzzed using `fuzzamoto-libafl` (custom fuzzer for
  [Fuzzamoto IR](./ir.md)).
