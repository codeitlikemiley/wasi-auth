#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "${REPO_ROOT}"

require_command cargo
require_command rustup
target="wasm32-wasip2"
if ! rustup target list --installed | grep -Fxq "${target}"; then
    echo "error: Rust target ${target} is not installed for the pinned toolchain" >&2
    echo "install it with: rustup target add ${target} --toolchain $(compat_value rust)" >&2
    exit 1
fi

mkdir -p "${COMPONENT_ARTIFACT_DIR}" "${TEST_COMPONENT_ARTIFACT_DIR}"
rm -f "${COMPONENT_ARTIFACT_DIR}/"*.wasm "${TEST_COMPONENT_ARTIFACT_DIR}/"*.wasm

build_and_copy() {
    local package="$1"
    local rust_artifact="$2"
    local destination="$3"

    cargo build --locked --release --target "${target}" --package "${package}"
    local source="${REPO_ROOT}/target/${target}/release/${rust_artifact}.wasm"
    require_file "${source}"
    cp "${source}" "${destination}"
}

for component in "${COMPONENTS[@]}"; do
    package="wasi-http-middleware-${component}"
    rust_artifact="${package//-/_}"
    build_and_copy "${package}" "${rust_artifact}" "$(component_file "${component}")"
done

for component in "${CONFORMANCE_COMPONENTS[@]}"; do
    package="wasi-http-middleware-${component}"
    rust_artifact="${package//-/_}"
    build_and_copy "${package}" "${rust_artifact}" "$(test_component_file "${component}")"
done

for component in "${TEST_COMPONENTS[@]}"; do
    package="wasi-http-middleware-${component}"
    rust_artifact="${package//-/_}"
    build_and_copy "${package}" "${rust_artifact}" "$(test_component_file "${component}")"
done

echo "built middleware components in ${COMPONENT_ARTIFACT_DIR}"
echo "built conformance and test components in ${TEST_COMPONENT_ARTIFACT_DIR}"
