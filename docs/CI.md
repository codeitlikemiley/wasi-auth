# Continuous integration

The middleware history and compatibility sources are imported under
`legacy/wasi-http-middleware` at the exact revision in `compatibility.toml`.
Every CI job runs `scripts/check-sibling-source.sh`, which verifies that the
pinned source revision remains an ancestor of the consolidated repository.
There is no cross-repository path dependency or checkout prerequisite.

Blocking lanes cover:

- Rust 1.93 MSRV and current stable, Clippy, tests, doctests, rustdoc, and the
  public feature powerset through every pair;
- additive WASIp2, WASIp3, and dual-client builds;
- an explicit private-alpha API break inventory against `043f5b6`;
- AuthZEN vectors plus Cedar and SpiceDB providers;
- all ignored relational-kernel contracts against a migrated live PostgreSQL
  service, including transactional invalidation notification;
- a real SpiceDB/zed live test;
- exact final-WIT imports, exports, and capability denial;
- dependency/advisory policy;
- parser fuzz smoke tests;
- the single public, Cargo-verified `wasi-auth` package archive; and
- local OCI, SBOM, provenance, and cosign verification.

Cross-repository promotion CI also starts a direct guest baseline, native
trusted ingress, and the private Spin backend, then runs the generated
`benchmark_ingress_overhead.sh`, `benchmark_fullstack.sh`, and
`soak_fullstack.sh` gates. The paired gate compares the same protected Cedar
request rather than anonymous edge traffic.

Ignored production tests are not accepted as coverage. Ordinary Rust jobs do
not receive service credentials, so environment-dependent tests are marked
ignored there. Dedicated `postgres-live` and `spicedb-live` jobs execute every
such test explicitly and fail before testing if their required environment is
missing. `scripts/test-postgres-kernel-live.sh` also applies and verifies the
immutable migration catalog before and after the contracts.

The legacy API inventory is not a SemVer compatibility claim. The compatibility
packages are private and the gate only detects behavioral drift from
[`reports/semver/alpha-api-inventory.md`](../reports/semver/alpha-api-inventory.md).
The final `wasi-auth 0.1.0-rc.2` revision becomes the public baseline for
subsequent release checks. No CI lane checks out DDD: the authentication crate,
package archive, and PostgreSQL live runner are independently releasable.
`PACKAGE_STRUCTURAL_ONLY=1` exists for archive inspection only and is never
release evidence.

## Provisioning an agent session

`.claude/hooks/session-start.sh` provisions a Claude Code on the web container
with the same tools the lanes above use. It runs only when
`CLAUDE_CODE_REMOTE=true`, so a local checkout is left alone.

It runs asynchronously: the session starts immediately and provisioning
continues behind it. That trades a wait for a race, so the hook writes
`$HOME/.cache/leptos-wasi-tools/.ready` as its final act. Anything needing
certainty before it runs a gate can block on that marker:

```bash
until [ -f "$HOME/.cache/leptos-wasi-tools/.ready" ]; do sleep 1; done
```

The marker is deleted at the start of every run, so its presence always means
the current run finished — never that some earlier one did. Its contents are
`complete`, or `incomplete: <tools>` naming whatever failed. A failed download
never aborts the session; re-running the hook retries only what is missing.

It hardcodes no versions. Every one is read through `compat_value` from
[`compatibility.toml`](../compatibility.toml), the same accessor the release
scripts use, so bumping a version there is enough.

Downloaded binaries — `wasm-tools`, `wasmtime`, `cosign`, `oras` — install to
`$HOME/.cache/leptos-wasi-tools/<name>-<version>/`, one of the locations
`resolve_pinned_tool` already searches. No environment variable is needed for
the scripts to find them, and because the cache sits outside the working tree
it survives both a fresh clone and `cargo clean`.

Cargo subcommands install to `$CARGO_HOME/bin` from upstream release assets by
direct URL. Discovery-based installers do not work here: the managed container
answers 403 for the GitHub REST and GraphQL APIs, with or without a token,
while `releases/download/...` answers 200, so discovery concludes no prebuilt
binary exists and falls back to a multi-minute source build per tool. Direct
URLs keep a cold run at roughly eight seconds. `cargo-binstall` and
`cargo install` remain as fallbacks if an asset is renamed upstream.

`cargo-cyclonedx` is the exception and is built from source. It publishes no
upstream binary, and taking the tool that generates this repository's SBOMs
from an unattested third-party rebuild is not a trade worth making.

The hook never writes to the working tree. `cargo fetch` runs with `--locked`
so it cannot rewrite a lockfile and leave `require_clean_tree` failing, and
`fuzz/` is skipped for that reason — its lockfile trails its manifest.

Two stages are off by default because they are large and rarely needed:

| Variable | Effect |
|---|---|
| `WASI_AUTH_SETUP_FUZZ=1` | installs the pinned nightly toolchain and `cargo-fuzz` |
| `WASI_AUTH_SETUP_PROVIDERS=1` | installs checksum-verified SpiceDB and zed, and exports `SPICEDB_BIN`/`ZED_BIN` |
| `WASI_AUTH_SETUP_SKIP_CARGO_TOOLS=1` | skips the cargo subcommands |
| `WASI_AUTH_SETUP_SKIP_FETCH=1` | skips prefetching the three lockfiles |

The PostgreSQL lanes need a live server rather than a binary, so the hook does
not provision one; export `WASI_AUTH_POSTGRES_TEST_URL` against a reachable
instance to run them.
