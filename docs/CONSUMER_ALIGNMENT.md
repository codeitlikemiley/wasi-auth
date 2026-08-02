# Consumer alignment: `leptos_wasi` from `0.1.0-alpha.4` to `0.1.0-rc.1`

This records what `leptos_wasi` must change to move its pin of this repository
from `wasi-auth 0.1.0-alpha.4` to `0.1.0-rc.1`, and what this repository
produced for it. Nothing in `leptos_wasi` was modified to produce this; every
build check below ran against a scratch copy.

Verified against `leptos_wasi` `main` = `fa424c1` and this repository at
`f53f73e`. The `0.1.0-alpha.4` baseline is `901d283`, the last commit carrying
that workspace version.

## 1. API surface

**Every symbol the consumer imports is unchanged.** The evidence is stronger
than a signature comparison:

```
git diff --stat 901d283 f53f73e -- \
  crates/leptos-wasi-authz crates/wasi-authz-client crates/wasi-authz-contract \
  crates/wasi-authz-cedar crates/wasi-authz-spicedb \
  legacy/wasi-http-middleware/crates/authn
```

reports changes to three `Cargo.toml` files and **no `.rs` file at all**. The
three edits are internal path-dependency pins (`wasi-authz-http` and
`wasi-authz-testkit`) moving from `=0.1.0-alpha.4` to `=0.1.0-rc.1`; neither
crate is part of the consumer's import surface. `legacy/wasi-http-middleware`
is byte-identical across the range, so `wasi-http-authn 0.2.0-alpha.3` is the
same code the consumer already compiles.

The consumer imports 24 symbols, not the 20 previously catalogued —
`wasi_authz_cedar::CedarProvider` and
`wasi_authz_spicedb::{PermissionMap, SpiceDbEndpoint, SpiceDbProvider}` were
missing from the earlier list. All 24 are listed below with their definition
sites at `0.1.0-rc.1`.

| Crate | Symbol | Kind | Defined at | Verdict |
|---|---|---|---|---|
| `leptos-wasi-authz` | `RequireAuthLayer` | struct | `src/lib.rs:598` | unchanged |
| | `ResponseStatusSink` | struct | `src/lib.rs:59` | unchanged |
| | `authorize_current` | async fn | `src/lib.rs:452` | unchanged |
| | `authorize_current_relationship` | async fn | `src/lib.rs:479` | unchanged |
| | `authorize_current_hybrid_with_consistency` | async fn | `src/lib.rs:534` | unchanged |
| | `provide_auth_context` | fn | `src/lib.rs:279` | unchanged |
| | `provide_response_status_sink` | fn | `src/lib.rs:88` | unchanged |
| `wasi-authz-client` | `BearerAuthTransport` | struct | `src/lib.rs:55` | unchanged |
| | `AuthzenClient` | struct | `src/lib.rs:359` | unchanged |
| | `AuthzenEndpoint` | struct | `src/lib.rs:256` | unchanged |
| | `ClientError` | enum | `src/lib.rs:336` | unchanged |
| | `TransportError` | enum | `src/lib.rs:206` | unchanged |
| | `wasip3::Wasip3Transport` | struct | `src/wasip3.rs:14` | unchanged |
| | `wasip2::Wasip2Transport` | struct | `src/wasip2.rs:92` | unchanged |
| | `wasip2::PollableWaiter` | trait | `src/wasip2.rs:69` | unchanged |
| | `wasip2::PollableWaitError` | enum | `src/wasip2.rs:77` | unchanged |
| | `wasip2::PollableWaitFuture` | type alias | `src/wasip2.rs:26` | unchanged |
| `wasi-authz-contract` | `AccessEvaluation` | alias of `AccessRequestV1` | `src/lib.rs:895` | unchanged |
| | `Action` | alias of `ActionV1` | `src/lib.rs:897` | unchanged |
| | `Resource` | alias of `ResourceV1` | `src/lib.rs:899` | unchanged |
| | `Consistency` | alias of `ConsistencyRequirementV1` | `src/lib.rs:901` | unchanged |
| | `AttributesV1` | struct | `src/lib.rs:473` | unchanged |
| | `AttributeV1` | struct | `src/lib.rs:405` | unchanged |
| | `AttributeNameV1` | struct | `src/lib.rs:217` | unchanged |
| | `AttributeValueV1` | enum | `src/lib.rs:379` | unchanged |
| | `AttributeStringV1` | struct (`bounded_text_type!`) | `src/lib.rs:316` | unchanged |
| | `AttributeProvenanceV1` | enum | `src/lib.rs:327` | unchanged |
| `wasi-authz-cedar` | `CedarProvider` | struct | `src/lib.rs:71` | unchanged |
| `wasi-authz-spicedb` | `SpiceDbEndpoint` | struct | `src/lib.rs:41` | unchanged |
| | `PermissionMap` | struct | `src/lib.rs:105` | unchanged |
| | `SpiceDbProvider` | struct | `src/lib.rs:184` | unchanged |
| `wasi-http-authn` | `AuthenticationConfigError` | enum | `src/lib.rs:86` | unchanged |
| | `TrustedIngressConfig` | struct | `src/lib.rs:193` | unchanged |
| | `accept_trusted_ingress` | fn | `src/lib.rs:220` | unchanged |

Both `wasip2` and `wasip3` feature paths still exist and both modules are still
public under those exact names.

### Confirmed by compiling, not by reading

Both consumer fixtures were compiled against this branch with Rust 1.93.0 for
`wasm32-wasip2`, in a scratch tree with `wasi-auth` as the expected sibling:

- `tests/authz-fixture` (wasip3, all 24 symbols) — `cargo check --locked
  --all-targets` exits 0 once its five `=0.1.0-alpha.4` pins read
  `=0.1.0-rc.1`. Left unedited it fails to resolve, which is the only thing
  that fails.
- `tests/authz-lifecycle-wasip2` — `cargo check --locked --all-targets` exits 0
  with **no edit at all**. It declares `wasi-authz-client` and
  `wasi-authz-contract` by path with no version requirement, so nothing needs
  bumping. `default-features = false, features = ["wasip2"]` still resolves to
  the same surface.

Nothing beyond the version pins has to change on the consumer side.

## 2. Artifact names and stack order

Both still hold at `0.1.0-rc.1`.

`reports/wit/` is byte-identical between `901d283` and `f53f73e`, so the
component contracts did not move at all.

| Locked component | Source directory | Cargo package | Built artifact |
|---|---|---|---|
| `authz-http-pep` | `components/http-pep` | `wasi-authz-http-pep` | `components/authz-http-pep.wasm` |
| `cedar-pdp` | `components/cedar-pdp` | `wasi-authz-cedar-pdp-component` | `components/cedar-pdp.wasm` |
| `spicedb-pdp` | `components/spicedb-pdp` | `wasi-authz-spicedb-pdp-component` | `components/spicedb-pdp.wasm` |

The source directory and artifact name of the HTTP PEP differ deliberately.
Both names are now recorded in `companion.toml` so neither has to be inferred.

Stack order is enforced entirely on the consumer side, but what determines the
PEP's *position* is produced here and is unchanged. `check-component-contracts.sh`
asserts, and this run confirms, that `authz-http-pep` has exactly one
`import wasi:http/handler@0.3.0` and one `export` of the same — the shape of a
chainable middleware that wraps a downstream handler, so it still sits last in
the chain, immediately before the terminal. Both PDPs export the handler and
import none, so they remain terminals outside the HTTP chain and take no
position in the stack. No component was added or removed since `alpha.4`.

`legacy/wasi-http-middleware/components/` still contains all five locked
middleware components (`request-id`, `security-headers`, `cors`,
`authn-policy`, `secure-defaults`) plus `passthrough`.

## 3. The regenerated bundle

Produced from a clean, non-dirty tree at revision
`f53f73e50e2861828237d1cb3318e9b1747982b8` on Ubuntu 24.04.4 / x86_64 /
Rust 1.93.0 — the canonical CI lane — with `wasm-tools 1.253.0`,
`cargo-cyclonedx 0.5.9`, `cosign 3.1.1`, `oras 1.3.2`.

The component build embeds absolute source paths, so its digest depends on the
checkout path and `CARGO_HOME`. Rebuilt under the CI's exact layout, all three
components reproduce the tracked `artifacts/SHA256SUMS` **byte for byte**; the
tracked checksums at `rc.1` were already correct and needed no refresh.
`reports/wit`, `artifacts/sbom`, and `companion.toml` also regenerate with no
drift.

Values the consumer should record:

```
artifact_name    = "wasi-authz"
artifact_version = "0.1.0-rc.1"
artifact_revision = "f53f73e50e2861828237d1cb3318e9b1747982b8"
```

| Component | `sha256` | `sbom_sha256` | `wit_sha256` |
|---|---|---|---|
| `authz-http-pep` | `29f6d86f…e1d5bb96` | `cd21bb20…b68da086` | `de6325ca…f55912d93` |
| `cedar-pdp` | `ffa1869a…f53f4074f` | `d77ec229…0d0dd552` | `7394503e…af75629e` |
| `spicedb-pdp` | `c57b6c7d…92d1cde1` | `0adfc137…cc75c40d` | `7d602957…f87855a2c0` |

| Evidence file | sha256 |
|---|---|
| `artifacts/RELEASE-SHA256SUMS` | `f0f1a0b70ebd81d7f97388604e4ae81c40872792af46452ae69d978277236fd0` |
| `artifacts/provenance.intoto.json` | `12b8fcf41df2e11a2e2912c4db7bfc5a21294d64ca5531a2b5893c8433762913` |
| `reports/supply-chain/manifest.json` | `35124e06b5440c7a13c5639eeed7e6122660f6ac3266519f3012231e53695f6d` |

The OCI artifact digest is
`sha256:35124e06b5440c7a13c5639eeed7e6122660f6ac3266519f3012231e53695f6d`,
artifact type `application/vnd.wasi.authz.bundle.v1`.

### What "attested" does and does not mean here

Signing genuinely ran. `cosign sign-blob` produced detached bundles over both
the provenance statement and the OCI manifest, and `cosign verify-blob`
returned `Verified OK` for both. But this is `dry-run-supply-chain.sh`, which
generates an **ephemeral** key, publishes the public half, and deletes the
private half. It is proof of assembly and signature verification, not a release
identity. A real release must sign with an authorized CI identity or a
protected key and publish transparency evidence.

**This has a consequence for the consumer's lock design.** Running the pipeline
twice at the same revision shows:

- `artifacts/provenance.intoto.json` — reproducible
- `reports/supply-chain/manifest.json` — reproducible
- `reports/supply-chain/cosign.pub` — **differs every run**
- `reports/supply-chain/*.sigstore.json` — **differs every run**

So `signing_key_sha256`, `provenance_signature_sha256`, and
`manifest_signature_sha256` in the consumer's `artifact-sets.toml` pin files
that change on every CI run. Those digests can only be satisfied by pinning one
immutable published bundle, or by switching the release to a stable signing
key. Regenerating the bundle will not reproduce them.

Also note: `reports/supply-chain/` and `artifacts/RELEASE-SHA256SUMS` are
git-ignored by design. The bundle is a CI upload artifact, not repository
content, so the consumer must pull it from the run for `artifact_revision`.

## 4. Proposed consumer changes

Proposals only — not applied here.

### `tests/authz-fixture/Cargo.toml`

Five lines. `wasi-http-authn` stays at `=0.2.0-alpha.3`; that crate genuinely
did not move.

```diff
-leptos-wasi-authz = { path = "../../../wasi-auth/crates/leptos-wasi-authz", version = "=0.1.0-alpha.4" }
+leptos-wasi-authz = { path = "../../../wasi-auth/crates/leptos-wasi-authz", version = "=0.1.0-rc.1" }
-wasi-authz-client = { path = "../../../wasi-auth/crates/wasi-authz-client", version = "=0.1.0-alpha.4", features = ["wasip3"] }
+wasi-authz-client = { path = "../../../wasi-auth/crates/wasi-authz-client", version = "=0.1.0-rc.1", features = ["wasip3"] }
-wasi-authz-cedar = { path = "../../../wasi-auth/crates/wasi-authz-cedar", version = "=0.1.0-alpha.4" }
+wasi-authz-cedar = { path = "../../../wasi-auth/crates/wasi-authz-cedar", version = "=0.1.0-rc.1" }
-wasi-authz-contract = { path = "../../../wasi-auth/crates/wasi-authz-contract", version = "=0.1.0-alpha.4" }
+wasi-authz-contract = { path = "../../../wasi-auth/crates/wasi-authz-contract", version = "=0.1.0-rc.1" }
-wasi-authz-spicedb = { path = "../../../wasi-auth/crates/wasi-authz-spicedb", version = "=0.1.0-alpha.4" }
+wasi-authz-spicedb = { path = "../../../wasi-auth/crates/wasi-authz-spicedb", version = "=0.1.0-rc.1" }
```

### `tests/authz-lifecycle-wasip2/Cargo.toml`

**No change.** It is path-only with no version requirement and compiles against
`rc.1` unmodified. Worth pinning `version = "=0.1.0-rc.1"` on both entries for
consistency with the other fixture, but that is a hygiene choice, not a
requirement.

### `tests/middleware/components.lock.toml`

```diff
 [authorization]
 name = "wasi-auth"
-version = "0.1.0-alpha.4"
+version = "0.1.0-rc.1"
 relative_path = "../wasi-auth"
 leptos_package = "leptos-wasi-authz"
 leptos_crate_path = "crates/leptos-wasi-authz"
 client_package = "wasi-authz-client"
 client_crate_path = "crates/wasi-authz-client"
-baseline_revision = "27689e087af7946ff280102dbec94fb9b2fe0590"
-source_revision = "1bf80347b2fdff65408f3d239ff6f02b1033658e"
-# Last signed pre-consolidation bundle. Release promotion must regenerate and
-# attest an alpha.4 wasi-auth bundle from a clean consolidated revision.
+baseline_revision = "27689e087af7946ff280102dbec94fb9b2fe0590"
+source_revision = "f53f73e50e2861828237d1cb3318e9b1747982b8"
 artifact_name = "wasi-authz"
-artifact_version = "0.1.0-alpha.3"
-artifact_revision = "d4a755e7a4a5abe3b38868a71b063bf33592254c"
+artifact_version = "0.1.0-rc.1"
+artifact_revision = "f53f73e50e2861828237d1cb3318e9b1747982b8"
 fixture_manifest = "tests/authz-fixture/Cargo.toml"
```

`components` is unchanged — `authz-http-pep`, `cedar-pdp`, `spicedb-pdp` are
still exactly right.

Two revisions in the current lock cannot be resolved and should be dropped or
replaced rather than carried forward:

- `[authorization].artifact_revision = "d4a755e…"` does not exist in this
  repository's history.
- `[middleware].baseline_revision = "6977a75…"` does not exist here either. It
  is `[release].semver_baseline` from the standalone `wasi-http-middleware`
  repository, whose history predates the subtree import. If the field must
  survive, source it from `legacy/wasi-http-middleware/compatibility.toml`
  rather than from this repository's git history.

Also note `[authorization].source_revision = "1bf8034…"` is a `0.1.0-alpha.3`
commit even though the section is labelled `0.1.0-alpha.4`.

`[middleware]` needs no change. That subtree is byte-identical, so
`0.2.0-alpha.3` and its `source_revision`/`artifact_revision` remain accurate.

### `tests/middleware/artifact-sets.toml`

The `authorization` bundle needs `name`/`version`/`source_revision` and all
per-artifact digests replaced with the section 3 values, plus new
`checksum_manifest_sha256`, `provenance_sha256`, and `oci_manifest_sha256`. The
three signature-related digests must come from whichever bundle is published —
see the reproducibility caveat above. `deployment-policy.toml`'s
`artifact_set_sha256` must then be recomputed.

## 5. RSA/ES256 signing change

**It touches nothing the consumer touches**, at compile time or at runtime.

The disabled private RSA/PSS signing paths live in `crates/wasi-auth`, which
the consumer does not depend on. The `rsa` crate enters that crate's graph only
through `jsonwebtoken v10.4.0`. `cargo tree` over the five companion crates in
this workspace finds no `rsa`, `jsonwebtoken`, `ring`, or `openssl` dependency
in any of them.

`wasi-http-authn` is the one crate that could plausibly have been affected,
since `accept_trusted_ingress` validates ingress metadata. Its complete
transitive graph is `http`, `thiserror`, `wasi-http-metadata`,
`wasi-http-policy-core`, `base64`, `serde`, `serde_json` — no cryptography of
any kind. It validates a *trusted* ingress boundary: it rejects any request
carrying an `Authorization` header, then checks service ID, audience, and
lifetime on already-parsed context. It never verifies a signature, so no
algorithm allowlist applies and no token that previously passed can now be
rejected. `legacy/wasi-http-middleware` is byte-identical across the range in
any case.

This confirms the preliminary finding from the consumer side.

## 6. The six-crate under-record

The consumer's lock recorded two crates while its fixtures depend on six. This
repository now publishes [`companion.toml`](../companion.toml), generated from
`cargo metadata` across both workspaces by
`scripts/generate-companion-manifest.sh` and drift-checked in CI. It records
every companion crate with its resolved version, owning workspace, and
publishability; every component with its source directory, artifact path, SBOM,
and WIT report; and the release-bundle evidence paths.

The reason the consumer cannot simply pin versions is visible in that file:

| Crate | Version | Workspace | Publishable |
|---|---|---|---|
| `leptos-wasi-authz` | `0.1.0-rc.1` | `wasi-auth` | no |
| `wasi-authz-cedar` | `0.1.0-rc.1` | `wasi-auth` | no |
| `wasi-authz-client` | `0.1.0-rc.1` | `wasi-auth` | no |
| `wasi-authz-contract` | `0.1.0-rc.1` | `wasi-auth` | no |
| `wasi-authz-spicedb` | `0.1.0-rc.1` | `wasi-auth` | no |
| `wasi-http-authn` | `0.2.0-alpha.3` | `wasi-http-middleware` | yes |

Five are `publish = false` and can never come from a registry, so a repository
revision is the only meaningful pin. The sixth sits in the excluded legacy
workspace on an independent version line. `wasi-http-authn` carries no
`publish` key, so Cargo would allow publishing it even though `docs/RELEASE.md`
describes the legacy packages as unpublishable — an inconsistency worth
resolving one way or the other.

The recommendation for the consumer's lock is to record all six from
`companion.toml` rather than two by hand:

```toml
[authorization]
# …
companion_manifest = "companion.toml"
companion_manifest_sha256 = "<digest of the pinned revision's companion.toml>"
```

and to derive the per-crate table from that file, so a rename or a version
bump here surfaces as a digest mismatch instead of a build break.

## 7. Not verified

- Runtime behaviour. Everything above is source, type-check, WIT-contract, and
  digest evidence. No Wasmtime execution, no composed middleware chain, and no
  consumer integration test was run.
- The consumer's audit script was read, not executed; it needs the regenerated
  bundle and a recomputed `deployment-policy.toml` digest first.
- The native Cedar PDP digest
  (`5fcedc61725b5ca431d07a7a5eeccb2a46b961afed071e7cf0339bb81ced5407`) has no
  tracked baseline to compare against, since `artifacts/native/` is git-ignored.
  It is path-dependent in the same way the components are.
- Whether `0.1.0-rc.1` is the version the consumer should target, as opposed to
  waiting for a stable release, is a release-management decision and not
  addressed here.
