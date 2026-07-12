#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "${REPO_ROOT}"
require_command cargo
require_clean_tree
VERSION="$(compat_value version)"
package_args=(--locked)
if [[ "${ALLOW_DIRTY:-0}" == "1" ]]; then
    package_args+=(--allow-dirty)
fi
if [[ "${PACKAGE_STRUCTURAL_ONLY:-0}" == "1" ]]; then
    package_args+=(--no-verify)
fi

cargo_command=(cargo)
if [[ -n "${DDD_CQRS_ES_SOURCE:-}" ]]; then
    ddd_source="$(cd "${DDD_CQRS_ES_SOURCE}" && pwd)"
    cargo_command+=(
        --config
        "patch.crates-io.ddd_cqrs_es.path='${ddd_source}'"
    )
fi

"${cargo_command[@]}" package "${package_args[@]}" --package wasi-auth

if [[ "${PACKAGE_STRUCTURAL_ONLY:-0}" == "1" ]]; then
    verification="a structural archive; Cargo build verification was explicitly skipped"
else
    verification="a Cargo-verified archive"
fi

cat <<EOF
The single public wasi-auth ${VERSION} package produced ${verification}.
Legacy authorization, Leptos bridge, service, and component packages are
publish=false compatibility fixtures and cannot be released independently.
No package was uploaded.
EOF
