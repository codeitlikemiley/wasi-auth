#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"

baseline="$(python3 - <<'PY'
import tomllib
with open("compatibility.toml", "rb") as source:
    print(tomllib.load(source)["release"]["semver_baseline"])
PY
)"
report="reports/semver/0.1.0-alpha.1-to-0.2.0-alpha.1.md"
migration="MIGRATION.md"
command=(cargo semver-checks --baseline-rev "${baseline}" --release-type minor)

expect_breaks() {
    local package="$1"
    local expected_summary="$2"
    shift 2
    local output
    output="$(mktemp "${TMPDIR:-/tmp}/wasi-http-semver.XXXXXX")"
    if "${command[@]}" -p "${package}" >"${output}" 2>&1; then
        cat "${output}" >&2
        rm -f "${output}"
        echo "expected documented semver breaks for ${package}" >&2
        exit 1
    fi
    grep -Fq -- "${expected_summary}" "${output}"
    for symbol in "$@"; do
        grep -Fq -- "${symbol}" "${output}" || {
            cat "${output}" >&2
            rm -f "${output}"
            echo "missing expected semver break ${symbol}" >&2
            exit 1
        }
        grep -Fq -- "${symbol}" "${report}"
        grep -Fq -- "${symbol}" "${migration}"
    done
    rm -f "${output}"
}

expect_breaks \
    wasi-http-metadata \
    "Summary semver requires new major version: 4 major and 0 minor checks failed" \
    Principal parse_principal insert_principal AUTH_SUBJECT_HEADER \
    AUTH_ISSUER_HEADER AUTH_SCOPES_HEADER MetadataError::InvalidIdentityValue \
    MetadataError::InvalidScopes MetadataError::InvalidHeader

expect_breaks \
    wasi-http-policy-core \
    "Summary semver requires new major version: 3 major and 0 minor checks failed" \
    PolicyRequest PolicySuccess parse_policy_response AuthDecision::Forbidden

"${command[@]}" -p wasi-http-middleware-component-support

echo "verified intentional 0.1 to 0.2 alpha semver changes against ${baseline}"
