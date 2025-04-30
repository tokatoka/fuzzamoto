# Fuzzamoto

Fuzzamoto provides a framework and fuzzing engine for coverage-guided fuzzing
of Bitcoin full node implementations.

* **Implementation Agnostic**: The same tests can target different protocol
  implementations and compare their behavior (e.g. [Bitcoin
  Core](https://github.com/bitcoin/bitcoin),
  [btcd](https://github.com/btcsuite/btcd),
  [libbitcoin](https://github.com/libbitcoin/libbitcoin), ...)
* **Holistic**: Tests are performed on the full system, not just isolated
  components, enabling the discovery of bugs that arise from the composition of
  different components
* **Coverage-Guided**: Fuzzing is guided by coverage feedback

*It is not meant to be a replacement for traditional fuzzing of isolated
components, but rather a complement to it.*

Check out the [book](https://dergoegge.github.io/fuzzamoto/index.html) for more information.

## Trophies

| Project                                                                | Bug                                                                   | Scenario           |
| :--------------------------------------------------------------------- | :-------------------------------------------------------------------- | :----------------- |
| [Bitcoin Core](https://github.com/bitcoin/bitcoin) | [`migratewallet` RPC assertion failure](https://github.com/bitcoin/bitcoin/issues/32111) | `wallet-migration` |
| [Bitcoin Core](https://github.com/bitcoin/bitcoin) | [`migratewallet` RPC assertion failure](https://github.com/bitcoin/bitcoin/issues/32112) | `wallet-migration` |
| [Bitcoin Core](https://github.com/bitcoin/bitcoin) | [assertion failure in `CheckBlockIndex`](https://github.com/bitcoin/bitcoin/issues/32173) | `rpc-generic` |
| [Bitcoin Core PR#30277](https://github.com/bitcoin/bitcoin/pull/30277) | [Remotely reachable assertion failure in `Miniketch::Deserialize`](https://github.com/bitcoin/bitcoin/pull/30277#issuecomment-2992101654) | `ir` |
