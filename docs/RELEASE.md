# Alpha release process

The prepared version is `0.1.0-alpha.3`. No command in the implementation phase
creates a remote, tag, registry push, or crates.io publication.

## Source order

1. Prepare `wasi-http-middleware 0.2.0-alpha.3` and record its immutable source
   revision in `compatibility.toml`.
2. Run every `wasi-authz` Rust, provider, component, fuzz, package, and supply
   chain gate from a clean tree.
3. Verify the full pinned chain in `leptos_wasi` before preparing its release.

`scripts/check-packages.sh` checks every package file set and creates the
standalone `wasi-authz-contract` archive. Cargo cannot even prepare dependent
archives until crates.io resolves their unpublished middleware or earlier
workspace dependencies; `--no-verify` does not bypass registry dependency
resolution. After each prerequisite exists, rerun with
`REGISTRY_DEPENDENCIES_READY=1` to prepare the remaining archives in order.
This is still not a publish dry run.

There is no prior public `wasi-authz` release, so a registry SemVer comparison
is impossible for this first alpha. `scripts/check-alpha-api-inventory.sh`
instead verifies the known private-alpha diagnostics for the contract and
testkit against `043f5b6`. It is an expected-break inventory, not a passing
compatibility report. The prepared `0.1.0-alpha.3` release commit is the future
SemVer baseline.

After a separate publication authorization, crates.io operations must occur in
this order, waiting for each exact version to become resolvable before the next:

1. middleware shared crates (`wasi-http-metadata`, `wasi-http-policy-core`, and
   component support) `0.2.0-alpha.3`;
2. `wasi-authz-contract`;
3. `wasi-authz-client`;
4. `wasi-authz-testkit`, `wasi-authz-http`, `wasi-authz-cedar`, and
   `wasi-authz-spicedb`; and
5. `leptos-wasi-authz`.

The HTTP PEP component, Cedar and SpiceDB PDP components, and native Cedar PDP
are deployment artifacts, not publishable crates. `cargo publish --dry-run
--locked` for registry-dependent crates remains blocked until the preceding
exact versions exist in the target registry. Treating `--no-verify` as proof of
publishability is prohibited.

Before requesting a release, regenerate metadata and require no diff:

```bash
bash scripts/build-components.sh
bash scripts/build-native-pdp.sh
bash scripts/check-component-contracts.sh
bash scripts/check-alpha-api-inventory.sh
bash scripts/test-cedar-pdp-live.sh
bash scripts/test-spicedb-live.sh
bash scripts/test-spicedb-pdp-wasmtime.sh
bash scripts/generate-checksums.sh
bash scripts/generate-native-checksums.sh
bash scripts/generate-sbom.sh
git diff --exit-code -- artifacts/SHA256SUMS artifacts/sbom reports/wit
bash scripts/check-packages.sh
bash scripts/dry-run-supply-chain.sh
```
