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
