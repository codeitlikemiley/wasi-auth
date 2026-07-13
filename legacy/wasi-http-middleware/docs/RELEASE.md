# Release process

## Compatibility lock

`compatibility.toml` pins Rust, final WIT, `wasip3`, `wit-bindgen`, Wasmtime,
`wasm-tools`, WAC, Spin canaries, fuzzing, and supply-chain tools. A release
changes the file and workspace package version together. WIT changes require
rebuilding every component, regenerating reports/SBOMs/checksums, and rerunning
all behavioral and incompatibility gates.

Rust 1.93.0 is the library MSRV. The component crates use `wasip3` 0.7.0 and
`wit-bindgen` 0.59.0 to export exact final `wasi:http@0.3.0`. Browser-side
`wasm-bindgen` is not part of this workspace; 0.2.126 is validated by the
sibling Leptos browser integration and must not be presented as a server
component dependency.

## Required gates

```bash
cargo fmt --all -- --check
cargo clippy --workspace --locked --all-targets --all-features -- -D warnings
cargo test --workspace --locked --all-features
cargo test --workspace --locked --doc
RUSTDOCFLAGS='-Dmissing-docs -Drustdoc::broken-intra-doc-links' \
  cargo doc --workspace --locked --no-deps --all-features
cargo audit --deny warnings
cargo deny check
bash scripts/check-semver-baseline.sh
bash scripts/check-packages.sh
bash scripts/build-components.sh
bash scripts/check-component-contracts.sh
bash scripts/run-wasmtime-e2e.sh
bash scripts/run-wasmtime-secure-defaults-e2e.sh
bash scripts/compare-wasmtime-profiles.sh
SPIN_COMPAT_PROFILE=stable-final bash scripts/run-spin-e2e.sh
SPIN_BIN="$(bash scripts/bootstrap-spin-main.sh default)" \
  SPIN_COMPAT_PROFILE=main-terminal bash scripts/run-spin-e2e.sh
SPIN_BIN="$(bash scripts/bootstrap-spin-main.sh default)" \
  SPIN_COMPAT_PROFILE=main-precomposed-default bash scripts/run-spin-e2e.sh
SPIN_BIN="$(bash scripts/bootstrap-spin-main.sh no-default-features)" \
  SPIN_COMPAT_PROFILE=main-precomposed-no-cpu bash scripts/run-spin-e2e.sh
SPIN_COMPAT_PROFILE=native-middleware \
  SPIN_BIN=/path/to/spin-at-27451471 bash scripts/run-spin-e2e.sh
CARGO_FUZZ_BIN=/path/to/cargo-fuzz bash scripts/run-fuzz-smoke.sh
bash scripts/generate-checksums.sh
bash scripts/generate-sbom.sh
bash scripts/dry-run-supply-chain.sh
HOST=wasmtime bash scripts/soak-runtime.sh
```

The tagged stable and pinned native-middleware profiles are expected-failure
canaries. Pinned Spin main `c34c584` has a positive final-terminal check, an
expected default-build CPU-accounting failure for WAC composition, and a
positive no-default-features diagnostic. The last result does not qualify a
production runtime. A support claim requires a tagged Spin release whose
ordinary build passes the complete behavioral, performance, and soak suites.

Component contracts validate async component-model encoding, exact imports,
one handler import/export, forbidden capabilities, deterministic WIT reports,
fixture isolation, and negative manifest audit cases. The two Wasmtime profiles
must also match golden status/header/body signatures, including CORS failure and
terminal stream errors.

## Artifact set

Production components:

```text
artifacts/components/request-id.wasm
artifacts/components/security-headers.wasm
artifacts/components/cors.wasm
artifacts/components/authn-policy.wasm
artifacts/components/secure-defaults.wasm
```

`artifacts/SHA256SUMS` also pins conformance/test components so integration
fixtures cannot silently drift. Deterministic CycloneDX files live under
`artifacts/sbom/`; exact component WIT lives under `reports/wit/`.

The `artifacts/` tree is generated locally or in CI and is intentionally not
committed. `dry-run-supply-chain.sh` builds a local OCI layout, creates deterministic
in-toto/SLSA-shaped provenance, generates an ephemeral local key, and signs and
verifies both provenance and the fetched OCI manifest. It performs no registry
push and deletes the private key. Promotion must replace the ephemeral key with
CI keyless signing or an approved release identity.

After the final version commit, regenerate all checksums, SBOMs, WIT reports,
and provenance because package versions and source revision are embedded.
Push, tag, registry upload, crates.io publication, and GitHub release creation
remain separate operator actions.

## Registry order

Implementation and release preparation do not publish crates. When an operator
authorizes the separate crates.io action, publish and verify in this order:

1. `wasi-http-metadata`;
2. `wasi-http-middleware-component-support` (independent of metadata and safe
   to publish before or after step 1);
3. wait until the registry index resolves the exact metadata alpha, then
   publish `wasi-http-policy-core`.

`policy-core` deliberately pins `wasi-http-metadata =0.2.0-alpha.1`. Before
step 1 reaches the registry, Cargo cannot perform the final package verification
for `policy-core`; `scripts/check-packages.sh` accepts only that exact blocker,
verifies the exact package file list and source manifest, and rejects every
other failure. Components and `authn-runtime` remain `publish = false`;
compiled WASM artifacts use the separate signed-bundle release process.

The gate verifies Cargo-produced archives for metadata and component-support.
For policy-core it verifies the exact Cargo package list and manifest metadata,
then attempts archive creation and accepts only Cargo's missing exact-metadata
registry error. The operator must rerun the same gate after step 1; at that
point the policy-core archive must be produced and verified before publication.

## Stable promotion

Do not remove the alpha suffix until claimed hosts implement the same final WIT,
performance/soak gates are blocking and green, identity/security review is
complete, and signed release provenance is verifiable without insecure flags.
