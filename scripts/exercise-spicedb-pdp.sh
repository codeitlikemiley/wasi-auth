#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command curl
require_command python3
: "${WASI_AUTHZ_TEST_PDP_URL:?run through scripts/with-spicedb-pdp-wasmtime.sh}"
: "${WASI_AUTHZ_TEST_PDP_BEARER_TOKEN:?missing PEP bearer from runtime harness}"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/wasi-authz-spicedb-exercise.XXXXXX")"
trap 'rm -rf "${temporary}"' EXIT
wrong_token="wrong-pep-component-secret-0123456789"

request() {
    local token="$1"
    local document="$2"
    local output="$3"
    local response_headers="${4:-/dev/null}"
    local args=(
        --silent --show-error --output "${output}" --write-out '%{http_code}'
        --dump-header "${response_headers}"
        --connect-timeout 1 --max-time 5
        --header 'content-type: application/json'
        --data-binary @"${document}"
    )
    if [[ -n "${token}" ]]; then
        args+=(--header "authorization: Bearer ${token}")
    fi
    curl "${args[@]}" "${WASI_AUTHZ_TEST_PDP_URL}"
}

missing_status="$(request "" "${REPO_ROOT}/fixtures/spicedb-pdp/allow.json" \
    "${temporary}/missing.json" "${temporary}/missing.headers")"
wrong_status="$(request "${wrong_token}" "${REPO_ROOT}/fixtures/spicedb-pdp/allow.json" \
    "${temporary}/wrong.json")"
allow_status="$(request "${WASI_AUTHZ_TEST_PDP_BEARER_TOKEN}" \
    "${REPO_ROOT}/fixtures/spicedb-pdp/allow.json" \
    "${temporary}/allow.json" "${temporary}/allow.headers")"
deny_status="$(request "${WASI_AUTHZ_TEST_PDP_BEARER_TOKEN}" \
    "${REPO_ROOT}/fixtures/spicedb-pdp/deny.json" \
    "${temporary}/deny.json" "${temporary}/deny.headers")"
deep_status="$(request "${WASI_AUTHZ_TEST_PDP_BEARER_TOKEN}" \
    "${REPO_ROOT}/fixtures/spicedb-pdp/deep.json" \
    "${temporary}/deep.json" "${temporary}/deep.headers")"
method_status="$(curl --silent --show-error --output "${temporary}/method.json" \
    --dump-header "${temporary}/method.headers" --write-out '%{http_code}' \
    --connect-timeout 1 --max-time 5 --request GET \
    --header "authorization: Bearer ${WASI_AUTHZ_TEST_PDP_BEARER_TOKEN}" \
    "${WASI_AUTHZ_TEST_PDP_URL}")"
wrong_path_status="$(curl --silent --show-error --output "${temporary}/wrong-path.json" \
    --write-out '%{http_code}' --connect-timeout 1 --max-time 5 \
    --header "authorization: Bearer ${WASI_AUTHZ_TEST_PDP_BEARER_TOKEN}" \
    --header 'content-type: application/json' \
    --data-binary @"${REPO_ROOT}/fixtures/spicedb-pdp/allow.json" \
    "${WASI_AUTHZ_TEST_PDP_URL%/access/v1/evaluation}/other")"
malformed_status="$(curl --silent --show-error --output "${temporary}/malformed.json" \
    --write-out '%{http_code}' --connect-timeout 1 --max-time 5 \
    --header "authorization: Bearer ${WASI_AUTHZ_TEST_PDP_BEARER_TOKEN}" \
    --header 'content-type: application/json' --data-binary 'not-json' \
    "${WASI_AUTHZ_TEST_PDP_URL}")"

[[ "${missing_status}" == "401" ]] \
    || { echo "error: missing PEP bearer was not rejected" >&2; exit 1; }
grep -Eiq '^www-authenticate:[[:space:]]*Bearer' "${temporary}/missing.headers" \
    || { echo "error: 401 response omitted the RFC 6750 Bearer challenge" >&2; exit 1; }
[[ "${wrong_status}" == "401" ]] \
    || { echo "error: wrong PEP bearer was not rejected" >&2; exit 1; }
[[ "${allow_status}" == "200" ]] \
    || { echo "error: live SpiceDB relation did not return an AuthZEN response" >&2; exit 1; }
[[ "${deny_status}" == "200" ]] \
    || { echo "error: live SpiceDB no-relation case did not return an AuthZEN response" >&2; exit 1; }
[[ "${deep_status}" == "503" ]] \
    || { echo "error: SpiceDB traversal-limit result did not fail closed" >&2; exit 1; }
[[ ! -s "${temporary}/deep.json" ]] \
    || { echo "error: traversal-limit failure exposed provider details" >&2; exit 1; }
[[ "${method_status}" == "405" ]] \
    || { echo "error: unsupported AuthZEN method did not return 405" >&2; exit 1; }
grep -Eiq '^allow:[[:space:]]*POST' "${temporary}/method.headers" \
    || { echo "error: 405 response omitted Allow: POST" >&2; exit 1; }
[[ "${wrong_path_status}" == "404" ]] \
    || { echo "error: non-AuthZEN path did not return 404" >&2; exit 1; }
[[ "${malformed_status}" == "400" ]] \
    || { echo "error: malformed AuthZEN request did not return 400" >&2; exit 1; }

for headers in missing allow deny deep method; do
    grep -Eiq '^cache-control:[[:space:]]*no-store' "${temporary}/${headers}.headers" \
        || { echo "error: SpiceDB PDP response omitted cache-control: no-store" >&2; exit 1; }
done

python3 - "${temporary}/allow.json" "${temporary}/deny.json" <<'PY'
import json
import pathlib
import sys

allow = json.loads(pathlib.Path(sys.argv[1]).read_text())
deny = json.loads(pathlib.Path(sys.argv[2]).read_text())
if allow.get("decision") is not True:
    raise SystemExit("live relation did not produce decision=true")
if deny.get("decision") is not False:
    raise SystemExit("live no-relation subject did not produce decision=false")
for name, document in (("allow", allow), ("deny", deny)):
    metadata = document.get("context", {}).get("wasi_authz", {})
    if metadata.get("policy_revision") != "live-schema-1":
        raise SystemExit(f"{name} response omitted the policy revision")
    if metadata.get("model") != "spicedb" or metadata.get("model_version") != "spicedb-1.54.0":
        raise SystemExit(f"{name} response omitted the SpiceDB model version")
    if not metadata.get("consistency_token"):
        raise SystemExit(f"{name} response omitted its SpiceDB consistency token")
PY

echo "validated live allow, no-relation deny, and fail-closed traversal limit through final-WASIp3 SpiceDB PDP"
