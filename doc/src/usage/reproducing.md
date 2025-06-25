# Reproducing Testcases

Crashing or other interesting inputs can be reproduced without the snapshotting
VM, by building the scenario binary without the nyx feature and supplying it
the input either through `stdin` or the `FUZZAMOTO_INPUT` environment variable.

Build all scenarios for reproduction purposes:

```
cargo build --release --package fuzzamoto-scenarios --features reproduce
```

`--features reproduce` is used to enable features useful for reproduction, e.g.
inherit stdout from the target application, such that any logs, stack traces,
etc. are printed to the terminal.


## `http-server` example

Run the scneario with the input supplied through `stdin` and pass the right
`bitcoind` binary:

```
cat ./testcase.dat | RUST_LOG=info ./target/release/scenario-http-server ./bitcoind
# Use "echo '<input base64>' | base64 --decode | ..." if you have the input as a base64 string
```

Or alternatively using `FUZZAMOTO_INPUT`:

```
FUZZAMOTO_INPUT=$PWD/testcase.dat RUST_LOG=info ./target/release/scenario-http-server ./bitcoind
```

## Troubleshooting

* Make sure to not use the `nyx` feature or else you'll see:
  ```
  ...
  Segmentation fault (core dumped)
  ```

* If you see the following output, try killing any left over `bitcoind`
  instances or retry reproduction until it works:
  ```
  ...
  Error: Unable to bind to 127.0.0.1:34528 on this computer. Bitcoin Core is probably already running.
  Error: Failed to listen on any port. Use -listen=0 if you want this.
  
  thread 'main' panicked at /fuzzamoto/vendor/corepc-node/src/lib.rs:389:59:
  failed to create client: Io(Os { code: 2, kind: NotFound, message: "No such file or directory" })
  ...
  ```

* If an input does not reproduce, check that you are compiling with all
  necessary features relevant for your case, such as `compile_in_vm`,
  `force_send_and_ping` and `reduced_pow` (these should all be enabled if
  compiling with the `reproduce` feature). Also check that `bitcoind` was build
  with all required patches applied (see
  [target-patches/](https://github.com/dergoegge/fuzzamoto/tree/master/target-patches)
  and [Patches](./target-patches.md)).

* If the input still does not reproduce (e.g. `bitcoind` does not crash), the
  crash might be non-deterministic. Have fun debugging!
