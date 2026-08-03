# Consumer alignment: `leptos_wasi` from `0.1.0-alpha.4` to `0.1.0-rc.2`

This records what `leptos_wasi` must change to move its pin of this repository
from `wasi-auth 0.1.0-alpha.4` to `0.1.0-rc.2`, and what this repository
produced for it. Nothing in `leptos_wasi` was modified to produce this; every
build check below ran against a scratch copy.

Verified against `leptos_wasi` `main` = `fa424c1` and this repository at
`e3e8ca5`. The `0.1.0-alpha.4` baseline is `901d283`, the last commit carrying
that workspace version.

## 1. API surface

**Every symbol the consumer imports is unchanged.** The evidence is stronger
than a signature comparison:

```
git diff --stat 901d283 e3e8ca5 -- \
  crates/leptos-wasi-authz crates/wasi-authz-client crates/wasi-authz-contract \
  crates/wasi-authz-cedar crates/wasi-authz-spicedb \
  legacy/wasi-http-middleware/crates/authn
```

reports changes to three `Cargo.toml` files and **no `.rs` file at all**. The
three edits are internal path-dependency pins (`wasi-authz-http` and
`wasi-authz-testkit`) moving from `=0.1.0-alpha.4` to `=0.1.0-rc.2`; neither
crate is part of the consumer's import surface. `legacy/wasi-http-middleware`
is byte-identical across the range, so `wasi-http-authn 0.2.0-alpha.3` is the
same code the consumer already compiles.

The consumer imports 24 symbols, not the 20 previously catalogued —
`wasi_authz_cedar::CedarProvider` and
`wasi_authz_spicedb::{PermissionMap, SpiceDbEndpoint, SpiceDbProvider}` were
missing from the earlier list. All 24 are listed below with their definition
sites at `0.1.0-rc.2`.

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
  `=0.1.0-rc.2`. Left unedited it fails to resolve, which is the only thing
  that fails.
- `tests/authz-lifecycle-wasip2` — `cargo check --locked --all-targets` exits 0
  with **no edit at all**. It declares `wasi-authz-client` and
  `wasi-authz-contract` by path with no version requirement, so nothing needs
  bumping. `default-features = false, features = ["wasip2"]` still resolves to
  the same surface.

Nothing beyond the version pins has to change on the consumer side.

## 2. Artifact names and stack order

Both still hold at `0.1.0-rc.2`.

`reports/wit/` is byte-identical between `901d283` and `e3e8ca5`, so the
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
`e3e8ca50090f192820af99fa061029a6aba6001f` on Ubuntu 24.04.4 / x86_64 /
Rust 1.93.0 — the canonical CI lane — with `wasm-tools 1.253.0`,
`cargo-cyclonedx 0.5.9`, `cosign 3.1.1`, `oras 1.3.2`.

The component build embeds absolute source paths, so its digest depends on the
checkout path and `CARGO_HOME`. Rebuilt under the CI's exact layout, all three
components reproduce the tracked `artifacts/SHA256SUMS` **byte for byte**, and
`reports/wit`, `artifacts/sbom`, and `companion.toml` all regenerate with no
drift.

Those tracked checksums are correct only because they were refreshed first. The
tree that shipped as `0.1.0-rc.2` bumped every manifest but never regenerated
its artifact metadata, so all fourteen SBOMs still described `rc.1` and all
three component digests were stale — the crate version is embedded in each
component, so bumping it moves every digest. That is repository-only: the
published crate is rooted at `crates/wasi-auth` and `artifacts/` sits at the
repository root, so no SBOM or checksum was ever inside the published tarball.
It still mattered here, because a consumer pins this repository by revision.

The WIT reports did **not** move. `reports/wit/*.wit` is byte-identical between
`rc.1` and `rc.2`, which is the expected result: the contracts carry no crate
version, so the component interfaces are unchanged and only embedded metadata
differs.

Values the consumer should record:

```
artifact_name    = "wasi-authz"
artifact_version = "0.1.0-rc.2"
artifact_revision = "e3e8ca50090f192820af99fa061029a6aba6001f"
```

That is the revision the bundle was built from. Anything committed after it on
this branch is documentation only — this file — and touches no build input, so
it does not invalidate the bundle. A real release should still cut a tag at the
revision it signs.

| Component | `sha256` | `sbom_sha256` | `wit_sha256` |
|---|---|---|---|
| `authz-http-pep` | `c838663b…a9dad15a` | `9613dd95…45af813d` | `de6325ca…f55912d93` |
| `cedar-pdp` | `1d898a75…f883c8a924` | `32790d27…8cd20ac4` | `7394503e…af75629e` |
| `spicedb-pdp` | `006ca504…c8eb1f41` | `f899dea7…da0118bd` | `7d602957…f87855a2c0` |

| Evidence file | sha256 |
|---|---|
| `artifacts/RELEASE-SHA256SUMS` | `639dd60ddf55a4c8e30375618107a894b2f5a92241118394380814f1ede70e97` |
| `artifacts/provenance.intoto.json` | `597f7f1d4e82a17449b1a0cd734f51672423fe48855d873cd113c1d9e2aeb01d` |
| `reports/supply-chain/manifest.json` | `e9a301f8bdebc57288fe56d337e81d244e30442291e2daf1d2afd60f2906dd60` |

The OCI artifact digest is
`sha256:e9a301f8bdebc57288fe56d337e81d244e30442291e2daf1d2afd60f2906dd60`,
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

For completeness, the ephemeral-key outputs of the bundle produced here were:

| File | sha256 |
|---|---|
| `reports/supply-chain/provenance.intoto.json.sigstore.json` | `4c1aad8f16c35732d0ac470f34adc4d8ce530f714e45d1fd3a16a4b67fd00c7c` |
| `reports/supply-chain/manifest.json.sigstore.json` | `5132fa9f06b8e22ef287c303b0b3131fa55fc0bddde24913131bc99473d64534` |
| `reports/supply-chain/cosign.pub` | `f2055a61509e463c32d2ae93aa06dd90837f4bfd4bb3016eb1fec88d59f16535` |

Do not copy these into the consumer's lock unless that exact bundle is the one
published. Whichever bundle a release actually publishes supersedes them.

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
+leptos-wasi-authz = { path = "../../../wasi-auth/crates/leptos-wasi-authz", version = "=0.1.0-rc.2" }
-wasi-authz-client = { path = "../../../wasi-auth/crates/wasi-authz-client", version = "=0.1.0-alpha.4", features = ["wasip3"] }
+wasi-authz-client = { path = "../../../wasi-auth/crates/wasi-authz-client", version = "=0.1.0-rc.2", features = ["wasip3"] }
-wasi-authz-cedar = { path = "../../../wasi-auth/crates/wasi-authz-cedar", version = "=0.1.0-alpha.4" }
+wasi-authz-cedar = { path = "../../../wasi-auth/crates/wasi-authz-cedar", version = "=0.1.0-rc.2" }
-wasi-authz-contract = { path = "../../../wasi-auth/crates/wasi-authz-contract", version = "=0.1.0-alpha.4" }
+wasi-authz-contract = { path = "../../../wasi-auth/crates/wasi-authz-contract", version = "=0.1.0-rc.2" }
-wasi-authz-spicedb = { path = "../../../wasi-auth/crates/wasi-authz-spicedb", version = "=0.1.0-alpha.4" }
+wasi-authz-spicedb = { path = "../../../wasi-auth/crates/wasi-authz-spicedb", version = "=0.1.0-rc.2" }
```

### `tests/authz-lifecycle-wasip2/Cargo.toml`

**No change.** It is path-only with no version requirement and compiles against
`rc.2` unmodified. Worth pinning `version = "=0.1.0-rc.2"` on both entries for
consistency with the other fixture, but that is a hygiene choice, not a
requirement.

### `tests/middleware/components.lock.toml`

```diff
 [authorization]
 name = "wasi-auth"
-version = "0.1.0-alpha.4"
+version = "0.1.0-rc.2"
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
+source_revision = "e3e8ca50090f192820af99fa061029a6aba6001f"
 artifact_name = "wasi-authz"
-artifact_version = "0.1.0-alpha.3"
-artifact_revision = "d4a755e7a4a5abe3b38868a71b063bf33592254c"
+artifact_version = "0.1.0-rc.2"
+artifact_revision = "e3e8ca50090f192820af99fa061029a6aba6001f"
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
| `leptos-wasi-authz` | `0.1.0-rc.2` | `wasi-auth` | no |
| `wasi-authz-cedar` | `0.1.0-rc.2` | `wasi-auth` | no |
| `wasi-authz-client` | `0.1.0-rc.2` | `wasi-auth` | no |
| `wasi-authz-contract` | `0.1.0-rc.2` | `wasi-auth` | no |
| `wasi-authz-spicedb` | `0.1.0-rc.2` | `wasi-auth` | no |
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

`companion.toml` records ten crates, not six. The six above carry
`direct = true` — a consumer is supported in naming them. Four more carry
`direct = false`: `wasi-authz-http`, `wasi-authz-testkit`,
`wasi-http-metadata`, and `wasi-http-policy-core`. A consumer should not depend
on those directly, but they are not incidental. They must exist in the checkout
for a `--locked` build, and `wasi-http-metadata`'s types — `AuthContextV1`,
`AuthStateV1`, `PrincipalV1`, `VerifiedAuthContext` — are re-exported from
`leptos-wasi-authz`'s root, so a consumer handles them by value while never
naming the crate. The indirect set is derived from the resolved dependency
graph, so a new intermediate crate cannot appear unrecorded.

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
- Whether to wait for a stable release instead of tracking an RC is a
  release-management decision and not addressed here.

## 8. Why `rc.2` and not `rc.1` or `rc.3`

`0.1.0-rc.1` and `0.1.0-rc.2` were both published to crates.io on 2026-07-13.
Their `.cargo_vcs_info.json` records the trees they came from: `8374cf2` for
rc.1, `3b31527` for rc.2. Only rc.1's commit was on `main`; rc.2's sat on an
unmerged branch until it was landed deliberately, so that the registry and the
mainline history agree.

`rc.1` is therefore superseded, and this assessment targets `rc.2`.

`rc.3` was considered and rejected for this purpose. The metadata defect
described in section 3 never reached the registry, and the consumer pins this
repository by revision rather than consuming the published crate — so
"`rc.2` at revision `e3e8ca5`" is a precise, verifiable pin, and burning a
version number to correct metadata that was never published would buy nothing.

One defect in the published `rc.2` is real and is not fixed by any of this:
`Cargo.lock` **is** included in the published tarball, and the published lock
resolves `event-listener 5.4.1` (RUSTSEC-2026-0221) and yanked `spin 0.9.8`.
Since this crate ships a binary, `cargo install wasi-auth --locked` pulls the
advisory. The repository is fixed; the published tarball cannot be. That is an
argument for cutting `rc.3` on its own schedule — it does not block the
consumer, which never installs the binary.
