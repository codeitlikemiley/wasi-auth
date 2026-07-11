# Continuous integration

The workspace intentionally depends on unpublished `wasi-http-middleware`
crates. Every CI job checks out that sibling at the exact revision in
`compatibility.toml` and runs `scripts/check-sibling-source.sh`. A missing
repository, unavailable revision, mismatch, or dirty sibling fails the workflow;
there is no fallback vendor copy and no skipped “green” path.

At this local-only stage the GitHub checkout cannot succeed until the user
authorizes a middleware remote or release artifact. That is an explicit
promotion blocker, not a passing gate. Local sibling runs remain authoritative
until both repositories are remotely addressable.

Blocking lanes cover:

- Rust 1.93 MSRV and current stable, Clippy, tests, doctests, and rustdoc;
- additive WASIp2, WASIp3, and dual-client builds;
- an explicit private-alpha API break inventory against `043f5b6`;
- AuthZEN vectors plus Cedar and SpiceDB providers;
- a real SpiceDB/zed live test;
- exact final-WIT imports, exports, and capability denial;
- dependency/advisory policy;
- parser fuzz smoke tests;
- structural package archives; and
- local OCI, SBOM, provenance, and cosign verification.

Ignored production tests are not accepted as coverage. The ordinary Rust lane
may leave the environment-dependent SpiceDB test ignored only because the
dedicated `spicedb-live` job executes it explicitly.

The API inventory is not a SemVer compatibility claim. No `wasi-authz` crate
has a prior public release, and the two compared trees intentionally share the
same pre-release version. The gate forces patch analysis only to detect drift
from the exact findings recorded in
[`reports/semver/alpha-api-inventory.md`](../reports/semver/alpha-api-inventory.md).
If published, the final `0.1.0-alpha.3` release revision becomes the baseline
for subsequent release checks.
