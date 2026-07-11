#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "${REPO_ROOT}"
require_version cargo-semver-checks "$(compat_value cargo_semver_checks)"

baseline="$(compat_value initial_alpha_contract)"
if ! git cat-file -e "${baseline}^{commit}" 2>/dev/null; then
    echo "error: alpha API inventory baseline is unavailable: ${baseline}" >&2
    exit 1
fi

temporary_directory="$(mktemp -d)"
trap 'rm -rf "${temporary_directory}"' EXIT

run_expected_alpha_break() {
    local package="$1"
    local output="${temporary_directory}/${package}.log"
    shift

    set +e
    cargo semver-checks check-release \
        --package "${package}" \
        --baseline-rev "${baseline}" \
        --release-type patch \
        --color never >"${output}" 2>&1
    local status=$?
    set -e

    if [[ "${status}" -ne 1 ]]; then
        cat "${output}" >&2
        echo "error: expected an internal-alpha API diagnostic for ${package}, found exit ${status}" >&2
        exit 1
    fi
    if [[ "$(grep -c '^--- failure' "${output}")" -ne 1 ]]; then
        cat "${output}" >&2
        echo "error: ${package} has an unexpected number of semver diagnostic classes" >&2
        exit 1
    fi
    for expected in "$@"; do
        if ! grep -Fq -- "${expected}" "${output}"; then
            cat "${output}" >&2
            echo "error: ${package} alpha API inventory no longer contains: ${expected}" >&2
            exit 1
        fi
    done
    if ! grep -Fq -- "1 major and 0 minor checks failed" "${output}"; then
        cat "${output}" >&2
        echo "error: ${package} produced an unexpected semver summary" >&2
        exit 1
    fi
}

run_expected_alpha_break \
    wasi-authz-contract \
    "ContractError::CachingUnsupported" \
    "ContractError::UnsupportedDecisionContext"
run_expected_alpha_break \
    wasi-authz-testkit \
    "trait wasi_authz_testkit::ConformanceProvider"

cat <<EOF
Verified the private alpha API inventory against ${baseline}.

This is an expected-break inventory, not a compatibility pass:
- two obsolete AuthZEN rejection variants were intentionally removed;
- cargo-semver-checks reports the testkit provider trait after its canonical
  definition moved, while the original import remains as a compile-tested
  public re-export.

There is no published wasi-authz release to use as a registry baseline.
EOF
