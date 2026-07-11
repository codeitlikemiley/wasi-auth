#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command git
require_command python3
bash "${REPO_ROOT}/scripts/assemble-release-checksums.sh" >/dev/null
require_file "${ARTIFACT_ROOT}/RELEASE-SHA256SUMS"
require_file "${REPORT_ROOT}/wit/http-pep.wit"
require_file "${REPORT_ROOT}/wit/cedar-pdp.wit"
require_file "${REPORT_ROOT}/wit/spicedb-pdp.wit"
version="$(compat_value version)"
revision="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
middleware_revision="$(compat_value wasi_http_middleware_revision)"
output="${1:-${ARTIFACT_ROOT}/provenance.intoto.json}"
python3 "${REPO_ROOT}/scripts/generate-provenance.py" \
    "${REPO_ROOT}" "${version}" "${revision}" "${middleware_revision}" \
    "${ARTIFACT_ROOT}/RELEASE-SHA256SUMS" "${REPORT_ROOT}/wit" "${output}"
echo "wrote ${output}"
