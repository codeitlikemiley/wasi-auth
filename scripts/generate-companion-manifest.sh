#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command cargo
require_command python3
output="${1:-${REPO_ROOT}/companion.toml}"
python3 "${REPO_ROOT}/scripts/generate-companion-manifest.py" \
    "${REPO_ROOT}" "${output}"
echo "wrote ${output}"
