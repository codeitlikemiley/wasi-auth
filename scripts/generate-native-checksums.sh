#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

artifact="$(native_pdp_file)"
require_file "${artifact}"
mkdir -p "${NATIVE_ARTIFACT_DIR}"
checksum="$(sha256_file "${artifact}" | awk '{print $1}')"
printf '%s  native/%s\n' "${checksum}" "$(basename "${artifact}")" \
    >"${NATIVE_ARTIFACT_DIR}/SHA256SUMS"
echo "wrote ${NATIVE_ARTIFACT_DIR}/SHA256SUMS"
