#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "${REPO_ROOT}"
require_command cargo
require_command rustup
target="$(compat_value component_target)"
toolchain="$(compat_value msrv)"
if ! rustup target list --installed --toolchain "${toolchain}" | grep -Fxq "${target}"; then
    echo "error: Rust target ${target} is not installed for ${toolchain}" >&2
    echo "install it with: rustup target add ${target} --toolchain ${toolchain}" >&2
    exit 1
fi

mkdir -p "${COMPONENT_ARTIFACT_DIR}"
rm -f "${COMPONENT_ARTIFACT_DIR}/"*.wasm
cargo build --locked --release --target "${target}" --package wasi-authz-http-pep
source_artifact="${REPO_ROOT}/target/${target}/release/wasi_authz_http_pep.wasm"
require_file "${source_artifact}"
cp "${source_artifact}" "${AUTHZ_COMPONENT}"
cargo build --locked --release --target "${target}" --package wasi-authz-cedar-pdp-component
source_cedar="${REPO_ROOT}/target/${target}/release/wasi_authz_cedar_pdp_component.wasm"
require_file "${source_cedar}"
cp "${source_cedar}" "${CEDAR_PDP_COMPONENT}"
cargo build --locked --release --target "${target}" --package wasi-authz-spicedb-pdp-component
source_spicedb="${REPO_ROOT}/target/${target}/release/wasi_authz_spicedb_pdp_component.wasm"
require_file "${source_spicedb}"
cp "${source_spicedb}" "${SPICEDB_PDP_COMPONENT}"

echo "built final-WASI components in ${COMPONENT_ARTIFACT_DIR}"
