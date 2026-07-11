#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_file "${ARTIFACT_ROOT}/SHA256SUMS"
require_file "${NATIVE_ARTIFACT_DIR}/SHA256SUMS"
temporary="${ARTIFACT_ROOT}/RELEASE-SHA256SUMS.tmp"
cat "${ARTIFACT_ROOT}/SHA256SUMS" "${NATIVE_ARTIFACT_DIR}/SHA256SUMS" \
    | LC_ALL=C sort >"${temporary}"
mv "${temporary}" "${ARTIFACT_ROOT}/RELEASE-SHA256SUMS"
echo "wrote ${ARTIFACT_ROOT}/RELEASE-SHA256SUMS"
