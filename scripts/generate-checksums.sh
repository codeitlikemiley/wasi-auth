#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_file "${AUTHZ_COMPONENT}"
require_file "${CEDAR_PDP_COMPONENT}"
require_file "${SPICEDB_PDP_COMPONENT}"
mkdir -p "${ARTIFACT_ROOT}"
temporary="${ARTIFACT_ROOT}/SHA256SUMS.tmp"
authz_checksum="$(sha256_file "${AUTHZ_COMPONENT}" | awk '{print $1}')"
cedar_checksum="$(sha256_file "${CEDAR_PDP_COMPONENT}" | awk '{print $1}')"
spicedb_checksum="$(sha256_file "${SPICEDB_PDP_COMPONENT}" | awk '{print $1}')"
printf '%s  components/authz-http-pep.wasm\n' "${authz_checksum}" >"${temporary}"
printf '%s  components/cedar-pdp.wasm\n' "${cedar_checksum}" >>"${temporary}"
printf '%s  components/spicedb-pdp.wasm\n' "${spicedb_checksum}" >>"${temporary}"
LC_ALL=C sort "${temporary}" >"${ARTIFACT_ROOT}/SHA256SUMS"
rm -f "${temporary}"

echo "wrote ${ARTIFACT_ROOT}/SHA256SUMS"
