#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

wasmtime_version="$(compat_value wasmtime)"
wasmtime_bin="$(resolve_pinned_tool WASMTIME_BIN wasmtime "${wasmtime_version}")"
require_command curl
require_command python3

chain="${ARTIFACT_ROOT}/composed/parity-chain.wasm"
fused="${ARTIFACT_ROOT}/composed/parity-secure-defaults.wasm"
broker="$(test_component_file mock-authn-broker)"
bash "${REPO_ROOT}/scripts/compose-wasmtime.sh" "$(test_component_file echo-service)" "${chain}"
bash "${REPO_ROOT}/scripts/compose-secure-defaults.sh" "$(test_component_file echo-service)" "${fused}"
require_file "${broker}"

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-parity.XXXXXX")"
pids=()
cleanup() {
    local pid
    for pid in "${pids[@]}"; do
        kill "${pid}" >/dev/null 2>&1 || true
    done
    for pid in "${pids[@]}"; do
        wait "${pid}" >/dev/null 2>&1 || true
    done
    rm -rf "${temporary_directory}"
}
trap cleanup EXIT

broker_address="127.0.0.1:19391"
broker_url="http://${broker_address}/authenticate"
"${wasmtime_bin}" serve \
    -W component-model-async=y -S p3=y -S cli=y -S http=y \
    --addr "${broker_address}" "${broker}" \
    >"${temporary_directory}/broker.log" 2>&1 &
pids+=("$!")

for _ in $(seq 1 100); do
    status="$(curl --silent --max-time 1 --request POST --output /dev/null --write-out '%{http_code}' "${broker_url}" || true)"
    [[ "${status}" == "401" ]] && break
    sleep 0.1
done
[[ "${status:-}" == "401" ]] || {
    echo "error: parity broker did not become ready" >&2
    exit 1
}

launch_app() {
    local address="$1"
    local component="$2"
    local log="$3"
    local cors="$4"
    local args=(
        "${wasmtime_bin}" serve
        -W component-model-async=y -S p3=y -S cli=y -S http=y -S inherit-network=y
        --env "WASI_MIDDLEWARE_AUTHN_BROKER_URL=${broker_url}"
        --env "WASI_MIDDLEWARE_AUTHN_TIMEOUT_MS=2000"
        --env "WASI_MIDDLEWARE_AUTHN_MODE=optional"
        --env "WASI_MIDDLEWARE_SERVICE_ID=echo-service"
        --env "WASI_MIDDLEWARE_AUTHN_AUDIENCES=api://echo-service"
        --env "WASI_MIDDLEWARE_AUTHN_MAX_IN_FLIGHT=64"
        --env "WASI_MIDDLEWARE_AUTHN_ALLOW_INSECURE_LOOPBACK=true"
    )
    if [[ "${cors}" == "configured" ]]; then
        args+=(
            --env "WASI_MIDDLEWARE_CORS_ORIGINS=https://app.example"
            --env "WASI_MIDDLEWARE_CORS_METHODS=GET,HEAD,POST"
            --env "WASI_MIDDLEWARE_CORS_HEADERS=content-type,authorization"
            --env "WASI_MIDDLEWARE_CORS_ALLOW_CREDENTIALS=false"
        )
    fi
    args+=(--addr "${address}" "${component}")
    "${args[@]}" >"${log}" 2>&1 &
    pids+=("$!")
}

wait_ready() {
    local url="$1"
    local expected="$2"
    local status=""
    for _ in $(seq 1 100); do
        status="$(curl --silent --max-time 1 --output /dev/null --write-out '%{http_code}' "${url}" || true)"
        [[ "${status}" == "${expected}" ]] && return 0
        sleep 0.1
    done
    echo "error: parity service did not become ready: ${url} (${status})" >&2
    return 1
}

chain_address="127.0.0.1:19390"
fused_address="127.0.0.1:19392"
launch_app "${chain_address}" "${chain}" "${temporary_directory}/chain.log" configured
launch_app "${fused_address}" "${fused}" "${temporary_directory}/fused.log" configured
wait_ready "http://${chain_address}/auth-contract" 200
wait_ready "http://${fused_address}/auth-contract" 200

capture() {
    local base="$1"
    local name="$2"
    local path="$3"
    shift 3
    local headers="${temporary_directory}/${name}.headers"
    local body="${temporary_directory}/${name}.body"
    local metadata="${temporary_directory}/${name}.metadata"
    set +e
    code="$(curl --silent --show-error --max-time 5 \
        --dump-header "${headers}" --output "${body}" --write-out '%{http_code}' \
        "$@" "${base}${path}")"
    curl_exit=$?
    set -e
    python3 - "${headers}" "${body}" "${code}" "${curl_exit}" >"${metadata}" <<'PY'
import hashlib
import pathlib
import sys

headers = pathlib.Path(sys.argv[1]).read_text(errors="replace").splitlines()
ignored = {"date", "x-request-id"}
normalized = []
for line in headers:
    if not line or line.lower().startswith("http/") or ":" not in line:
        continue
    name, value = line.split(":", 1)
    if name.lower() not in ignored:
        normalized.append(f"{name.lower()}:{value.strip()}")
body = pathlib.Path(sys.argv[2]).read_bytes()
print(f"status={sys.argv[3]}")
print(f"curl_exit={sys.argv[4]}")
print(f"body_sha256={hashlib.sha256(body).hexdigest()}")
for line in sorted(normalized):
    print(line)
PY
}

compare_case() {
    local name="$1"
    local path="$2"
    shift 2
    capture "http://${chain_address}" "chain-${name}" "${path}" "$@"
    capture "http://${fused_address}" "fused-${name}" "${path}" "$@"
    if ! diff -u \
        "${temporary_directory}/chain-${name}.metadata" \
        "${temporary_directory}/fused-${name}.metadata"; then
        echo "error: chain and secure-defaults differ for ${name}" >&2
        return 1
    fi
}

compare_case anonymous /auth-contract
compare_case allow /auth-contract \
    --header 'Authorization: Bearer allow' \
    --header 'x-wasi-auth-subject: attacker'
compare_case deny / --header 'Authorization: Bearer deny'
compare_case provider-error / --header 'Authorization: Bearer error'
compare_case redirect /redirect --header 'Authorization: Bearer allow'
compare_case not-found /missing --header 'Authorization: Bearer allow'
compare_case downstream-error /error --header 'Authorization: Bearer allow'
compare_case cors-vary / \
    --header 'Authorization: Bearer allow' \
    --header 'Origin: https://app.example'
compare_case preflight /echo \
    --request OPTIONS \
    --header 'Origin: https://app.example' \
    --header 'Access-Control-Request-Method: POST' \
    --header 'Access-Control-Request-Headers: content-type,authorization'
compare_case delayed /delayed --header 'Authorization: Bearer allow'
compare_case failing-stream /failing-stream --header 'Authorization: Bearer allow'

for headers in "${temporary_directory}"/{chain,fused}-allow.headers; do
    if grep -Eiq '^x-wasi-auth-' "${headers}"; then
        echo "error: trusted request metadata escaped in parity response" >&2
        exit 1
    fi
done

kill "${pids[1]}" "${pids[2]}" >/dev/null 2>&1 || true
wait "${pids[1]}" >/dev/null 2>&1 || true
wait "${pids[2]}" >/dev/null 2>&1 || true
pids=("${pids[0]}")
chain_bad="127.0.0.1:19490"
fused_bad="127.0.0.1:19492"
launch_app "${chain_bad}" "${chain}" "${temporary_directory}/chain-bad.log" missing
launch_app "${fused_bad}" "${fused}" "${temporary_directory}/fused-bad.log" missing
wait_ready "http://${chain_bad}/" 503
wait_ready "http://${fused_bad}/" 503
chain_address="${chain_bad}"
fused_address="${fused_bad}"
compare_case cors-config-failure /

assert_logs_do_not_contain_secrets \
    "${temporary_directory}/broker.log" \
    "${temporary_directory}/chain.log" \
    "${temporary_directory}/fused.log" \
    "${temporary_directory}/chain-bad.log" \
    "${temporary_directory}/fused-bad.log"

echo "Wasmtime chain and secure-defaults golden responses match"
