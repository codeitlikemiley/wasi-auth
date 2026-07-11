# Private alpha API inventory

This report compares only `wasi-authz-contract` and `wasi-authz-testkit` with
commit `043f5b6`, the first local contract/testkit checkpoint. Neither that
checkpoint nor any other `wasi-authz` version has been published. It is not a
public SemVer baseline.

`cargo-semver-checks 0.48.0` is deliberately run with
`--release-type patch` so it does not skip analysis merely because both trees
declare the same initial-alpha version. The expected diagnostics are:

| Package | Diagnostic | Disposition |
|---|---|---|
| `wasi-authz-contract` | `ContractError::CachingUnsupported` removed | Intentional pre-release correction. Unknown standard AuthZEN response context is ignored; this rejection variant would contradict AuthZEN 1.0. |
| `wasi-authz-contract` | `ContractError::UnsupportedDecisionContext` removed | Intentional pre-release correction for the same forward-compatibility rule. The reserved `wasi_authz` extension remains strict. |
| `wasi-authz-testkit` | `ConformanceProvider` reported missing | Analyzer artifact after the canonical trait moved to `wasi-authz-client`. The original testkit path remains a public re-export and is verified by `tests/public_api.rs`. |

The gate fails if a new diagnostic class appears or any expected diagnostic
disappears without updating this inventory. It intentionally succeeds only
after observing the known private-alpha findings; it must never be described
as a passing compatibility check.

The eventual `0.1.0-alpha.1` release commit becomes the first prospective
registry baseline. Every later release must compare all publishable crates to
that immutable release revision or registry version.
