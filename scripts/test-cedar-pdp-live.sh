#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command curl
require_command python3
binary="${CEDAR_PDP_BIN:-$(native_pdp_file)}"
require_file "${binary}"
port="$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')"
base="http://127.0.0.1:${port}"
token="cedar-live-bearer-token-do-not-log"
wrong_token="cedar-live-wrong-token-do-not-log"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/wasi-authz-cedar-live.XXXXXX")"
log="${temporary}/pdp.log"

cleanup() {
    status=$?
    trap - EXIT
    if [[ -n "${pdp_pid:-}" ]]; then
        kill "${pdp_pid}" 2>/dev/null || true
        wait "${pdp_pid}" 2>/dev/null || true
    fi
    for sentinel in \
        "${token}" \
        "${wrong_token}" \
        "leptos-wasi-counter" \
        "cold-start-probe"; do
        if grep -Fq -- "${sentinel}" "${log}"; then
            echo "error: Cedar PDP log disclosed request or credential data" >&2
            status=1
        fi
    done
    if [[ ${status} -ne 0 ]]; then
        tail -n 100 "${log}" >&2 || true
    fi
    rm -rf "${temporary}"
    exit "${status}"
}
trap cleanup EXIT

WASI_AUTHZ_CEDAR_LISTEN="127.0.0.1:${port}" \
WASI_AUTHZ_CEDAR_WORKERS=2 \
WASI_AUTHZ_CEDAR_POLICY_PATH="${REPO_ROOT}/fixtures/cedar/http_policy.cedar" \
WASI_AUTHZ_CEDAR_SCHEMA_PATH="${REPO_ROOT}/fixtures/cedar/http_schema.json" \
WASI_AUTHZ_CEDAR_ENTITIES_PATH="${REPO_ROOT}/fixtures/cedar/http_entities.json" \
WASI_AUTHZ_CEDAR_POLICY_REVISION=http-policy-1 \
WASI_AUTHZ_PDP_BEARER_TOKEN="${token}" \
    "${binary}" >"${log}" 2>&1 &
pdp_pid=$!

ready=false
for ((attempt = 0; attempt < 100; attempt += 1)); do
    status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
        --connect-timeout 1 --max-time 2 \
        --header 'content-type: application/json' \
        --data-binary @"${REPO_ROOT}/fixtures/cedar/http_public_request.json" \
        "${base}/access/v1/evaluation" || true)"
    if [[ "${status}" == "401" ]]; then
        ready=true
        break
    fi
    sleep 0.1
done
if [[ "${ready}" != true ]]; then
    echo "error: Cedar PDP did not become ready" >&2
    exit 1
fi

request() {
    local authorization="$1"
    local output="$2"
    local response_headers="${3:-/dev/null}"
    local args=(
        --silent --show-error --output "${output}" --write-out '%{http_code}'
        --dump-header "${response_headers}"
        --connect-timeout 1 --max-time 5
        --header 'content-type: application/json'
        --data-binary @"${REPO_ROOT}/fixtures/cedar/http_public_request.json"
    )
    if [[ -n "${authorization}" ]]; then
        args+=(--header "authorization: Bearer ${authorization}")
    fi
    curl "${args[@]}" "${base}/access/v1/evaluation"
}

missing_status="$(request "" "${temporary}/missing.json" "${temporary}/missing.headers")"
wrong_status="$(request "${wrong_token}" "${temporary}/wrong.json")"
allow_status="$(request "${token}" "${temporary}/allow.json")"
[[ "${missing_status}" == "401" ]] || { echo "error: missing bearer was not rejected" >&2; exit 1; }
grep -Eiq '^www-authenticate:[[:space:]]*Bearer' "${temporary}/missing.headers" \
    || { echo "error: 401 response omitted the Bearer challenge" >&2; exit 1; }
[[ "${wrong_status}" == "401" ]] || { echo "error: wrong bearer was not rejected" >&2; exit 1; }
[[ "${allow_status}" == "200" ]] || { echo "error: valid PEP request failed" >&2; exit 1; }
python3 -c '
import json, pathlib, sys
document = json.loads(pathlib.Path(sys.argv[1]).read_text())
if document.get("decision") is not True:
    raise SystemExit("allow response did not contain decision=true")
' "${temporary}/allow.json"

oversized_status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
    --connect-timeout 1 --max-time 5 \
    --request POST --header "authorization: Bearer ${token}" \
    --header 'content-length: 65537' "${base}/access/v1/evaluation")"
[[ "${oversized_status}" == "413" ]] \
    || { echo "error: oversized body declaration was not rejected" >&2; exit 1; }

echo "validated authenticated native Cedar PDP listener"
