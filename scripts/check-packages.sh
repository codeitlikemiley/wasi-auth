#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "${REPO_ROOT}"
require_command cargo
require_clean_tree
VERSION="$(compat_value version)"
MIDDLEWARE_VERSION="$(compat_value wasi_http_middleware)"
packages=(
    wasi-authz-contract
    wasi-authz-client
    wasi-authz-testkit
    wasi-authz-http
    wasi-authz-cedar
    wasi-authz-spicedb
    leptos-wasi-authz
)
package_args=(--locked --no-verify)
list_args=(--locked --list)
if [[ "${ALLOW_DIRTY:-0}" == "1" ]]; then
    package_args+=(--allow-dirty)
    list_args+=(--allow-dirty)
fi

for package in "${packages[@]}"; do
    cargo package "${list_args[@]}" --package "${package}" >/dev/null
done

# The root contract has no unpublished workspace or sibling dependency, so its
# actual archive can be prepared before the dependency release sequence starts.
cargo package "${package_args[@]}" --package wasi-authz-contract

if [[ "${REGISTRY_DEPENDENCIES_READY:-0}" == "1" ]]; then
    for package in "${packages[@]:1}"; do
        cargo package "${package_args[@]}" --package "${package}"
    done
fi

cat <<EOF
All package file sets passed structural checks and wasi-authz-contract produced
an archive. Dependent archives are intentionally unavailable until these exact
dependencies have been released:
  1. wasi-http-metadata, wasi-http-policy-core, and component-support ${MIDDLEWARE_VERSION}
  2. wasi-authz-contract ${VERSION}
  3. wasi-authz-client ${VERSION}
  4. wasi-authz-testkit and provider/PEP crates ${VERSION}
  5. leptos-wasi-authz ${VERSION}
No package was uploaded.
EOF
if [[ "${REGISTRY_DEPENDENCIES_READY:-0}" != "1" ]]; then
    echo "BLOCKED: set REGISTRY_DEPENDENCIES_READY=1 only after each preceding exact registry version resolves."
fi
