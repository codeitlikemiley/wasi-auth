#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "${REPO_ROOT}"
require_command cargo
require_command rustc
target="$(native_target)"
suffix=""
if [[ "${target}" == *windows* ]]; then
    suffix=".exe"
fi
cargo build --locked --release --target "${target}" --package wasi-authz-cedar-pdp
source_artifact="${REPO_ROOT}/target/${target}/release/wasi-authz-cedar-pdp${suffix}"
require_file "${source_artifact}"
mkdir -p "${NATIVE_ARTIFACT_DIR}"
rm -f "${NATIVE_ARTIFACT_DIR}/cedar-pdp-"*
cp "${source_artifact}" "$(native_pdp_file)"

echo "built target-qualified Cedar PDP: $(native_pdp_file)"
