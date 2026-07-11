#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command git
require_command python3
require_file "${ARTIFACT_ROOT}/SHA256SUMS"
version="$(compat_value version)"
revision="$(git -C "${REPO_ROOT}" rev-parse HEAD)"
output="${1:-${ARTIFACT_ROOT}/provenance.intoto.json}"
python3 "${REPO_ROOT}/scripts/generate-provenance.py" \
    "${REPO_ROOT}" "${version}" "${revision}" \
    "${ARTIFACT_ROOT}/SHA256SUMS" "${output}"
echo "wrote ${output}"
