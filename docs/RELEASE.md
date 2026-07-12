# Release-candidate process

The prepared version is `0.1.0-rc.1`. No command in the implementation phase
creates a remote, tag, registry push, or crates.io publication.

## Source order

1. Verify the imported middleware revision recorded in `compatibility.toml`.
2. Run every `wasi-auth` Rust, provider, component, migration, fuzz, package,
   and supply-chain gate from a clean tree.
3. Verify the full pinned chain in `leptos_wasi` and the generated DDD
   fullstack application before preparing a release.

`scripts/check-packages.sh` creates exactly one public archive: `wasi-auth`.
The legacy authorization packages, Leptos bridge, HTTP PEP, Cedar/SpiceDB PDP
components, and native Cedar PDP are all `publish = false` compatibility or
deployment artifacts.

There is no prior public `wasi-auth` release, so this RC becomes the first
SemVer baseline. `scripts/check-alpha-api-inventory.sh` remains a private
compatibility regression inventory and does not create additional supported
packages.

## Cross-repository publication order

The package graph, rather than repository ownership, determines publication
order:

1. `leptos-wasi-runtime 0.4.2-rc.1`, aliased as `leptos_wasi`;
2. the `ddd_cqrs_es 0.3.0-rc.1` library;
3. `wasi-auth 0.1.0-rc.1`;
4. `ddd-cqrs-es-cli 0.3.0-rc.1`; and
5. generated fullstack consumers.

`wasi-auth` optionally depends on `ddd_cqrs_es`, so the DDD library must exist
first. The CLI emits a manifest pinned to `wasi-auth`, so it follows this
crate. Stable releases repeat this topology. Never use an unpublished path or
git patch as registry-release evidence, and do not treat `--no-verify` as
proof of publishability.

The earlier proposed `leptos_wasi 0.4.0-alpha.3` number is not reusable because
the local release history already contains `0.4.0` and `0.4.1`.
`0.4.2-rc.1` preserves monotonic SemVer history for the final-WASI/islands
work.

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

During coordinated pre-publication integration only, run
`DDD_CQRS_ES_SOURCE=/absolute/path/to/ddd bash scripts/check-packages.sh`.
Cargo receives that source as external configuration and verifies the archive;
the packaged manifest remains registry-only. `PACKAGE_STRUCTURAL_ONLY=1`
deliberately skips Cargo's build verification and therefore cannot satisfy this
release gate.
