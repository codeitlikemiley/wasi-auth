# Continuous integration

The middleware history and compatibility sources are imported under
`legacy/wasi-http-middleware` at the exact revision in `compatibility.toml`.
Every CI job runs `scripts/check-sibling-source.sh`, which verifies that the
pinned source revision remains an ancestor of the consolidated repository.
There is no cross-repository path dependency or checkout prerequisite.

Blocking lanes cover:

- Rust 1.93 MSRV and current stable, Clippy, tests, doctests, and rustdoc;
- additive WASIp2, WASIp3, and dual-client builds;
- an explicit private-alpha API break inventory against `043f5b6`;
- AuthZEN vectors plus Cedar and SpiceDB providers;
- a real SpiceDB/zed live test;
- exact final-WIT imports, exports, and capability denial;
- dependency/advisory policy;
- parser fuzz smoke tests;
- the single public, Cargo-verified `wasi-auth` package archive; and
- local OCI, SBOM, provenance, and cosign verification.

Ignored production tests are not accepted as coverage. The ordinary Rust lane
may leave the environment-dependent SpiceDB test ignored only because the
dedicated `spicedb-live` job executes it explicitly.

The legacy API inventory is not a SemVer compatibility claim. The compatibility
packages are private and the gate only detects behavioral drift from
[`reports/semver/alpha-api-inventory.md`](../reports/semver/alpha-api-inventory.md).
The final `wasi-auth 0.1.0-alpha.4` revision becomes the public baseline for
subsequent release checks.

Before `ddd_cqrs_es 0.3.0-alpha.1` is published, coordinated source CI may set
`DDD_CQRS_ES_SOURCE` to that checkout. The package command receives the patch
through Cargo configuration, so no path enters the publishable manifest or
archive. `PACKAGE_STRUCTURAL_ONLY=1` exists for archive inspection only and is
never release evidence.
