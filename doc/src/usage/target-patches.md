# Custom Target Patches

Certain targets require custom patches for effective fuzzing and testcase
reproduction. These can be found in the
[`target-patches`](https://github.com/dergoegge/fuzzamoto/tree/master/target-patches)
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
- `bitcoin-core-aggressive-rng.patch`: Same as `bitcoin-core-rng.patch` but
  more aggressive
