#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command python3
wasmtime_version="$(compat_value wasmtime)"
wasmtime_bin="$(resolve_pinned_tool WASMTIME_BIN wasmtime "${wasmtime_version}")"
component="${CEDAR_PDP_COMPONENT_OVERRIDE:-${CEDAR_PDP_COMPONENT}}"
require_file "${component}"

python3 "${REPO_ROOT}/scripts/benchmark-cedar-pdp-wasmtime.py" \
    --wasmtime "${wasmtime_bin}" \
    --expected-version "${wasmtime_version}" \
    --component "${component}" \
    --request "${REPO_ROOT}/fixtures/cedar/http_public_request.json" \
    --cold-starts "${COLD_STARTS:-5}" \
    --requests "${LOAD_REQUESTS:-200}" \
    --concurrency "${LOAD_CONCURRENCY:-16}"
