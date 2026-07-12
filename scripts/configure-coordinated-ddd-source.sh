#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

if [[ -z "${DDD_CQRS_ES_SOURCE:-}" ]]; then
    echo "error: DDD_CQRS_ES_SOURCE is required" >&2
    exit 1
fi

ddd_source="$(cd "${DDD_CQRS_ES_SOURCE}" && pwd)"
require_file "${ddd_source}/Cargo.toml"
require_command git

expected_revision="$(compat_value ddd_revision)"
actual_revision="$(git -C "${ddd_source}" rev-parse HEAD)"
if [[ "${actual_revision}" != "${expected_revision}" ]]; then
    echo "error: coordinated DDD revision mismatch" >&2
    echo "expected: ${expected_revision}" >&2
    echo "actual:   ${actual_revision}" >&2
    exit 1
fi

config_root="${CARGO_HOME:-${HOME}/.cargo}"
mkdir -p "${config_root}"
config_file="${config_root}/config.toml"
if [[ -e "${config_file}" ]]; then
    echo "error: refusing to overwrite existing Cargo config: ${config_file}" >&2
    exit 1
fi

printf '[patch.crates-io]\nddd_cqrs_es = { path = "%s" }\n' "${ddd_source}" >"${config_file}"
echo "configured coordinated ddd_cqrs_es revision ${actual_revision}"
