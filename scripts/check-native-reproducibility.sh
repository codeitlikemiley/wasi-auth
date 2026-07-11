#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "${REPO_ROOT}"
require_command cargo
target="$(native_target)"
bash "${REPO_ROOT}/scripts/build-native-pdp.sh" >/dev/null
first="$(sha256_file "$(native_pdp_file)" | awk '{print $1}')"
cargo clean --release --target "${target}" --package wasi-authz-cedar-pdp
bash "${REPO_ROOT}/scripts/build-native-pdp.sh" >/dev/null
second="$(sha256_file "$(native_pdp_file)" | awk '{print $1}')"
if [[ "${first}" != "${second}" ]]; then
    echo "error: native Cedar PDP is not reproducible for target ${target}" >&2
    echo "first:  ${first}" >&2
    echo "second: ${second}" >&2
    exit 1
fi
echo "verified reproducible Cedar PDP for ${target}: ${second}"
