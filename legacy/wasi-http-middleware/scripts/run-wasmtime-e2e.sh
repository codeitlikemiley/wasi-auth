#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

wasmtime_version="$(compat_value wasmtime)"
wasmtime_bin="$(resolve_pinned_tool WASMTIME_BIN wasmtime "${wasmtime_version}")"
require_command curl

echo_component="${E2E_APP_COMPONENT:-$(test_component_file echo-service)}"
policy_component="${E2E_AUTHN_BROKER_COMPONENT:-$(test_component_file mock-authn-broker)}"
require_file "${echo_component}"
require_file "${policy_component}"

app_port="${E2E_APP_PORT:-19090}"
policy_port="${E2E_POLICY_PORT:-19091}"
app_address="127.0.0.1:${app_port}"
policy_address="127.0.0.1:${policy_port}"
policy_url="http://${policy_address}/authenticate"
authn_timeout_ms="${E2E_AUTHN_TIMEOUT_MS:-2000}"
if [[ -n "${E2E_COMPOSED_COMPONENT:-}" ]]; then
    composed="${E2E_COMPOSED_COMPONENT}"
    require_file "${composed}"
else
    profile="${E2E_MIDDLEWARE_PROFILE:-chain}"
    case "${profile}" in
        chain)
            composed="${ARTIFACT_ROOT}/composed/e2e-full-chain.wasm"
            bash "${REPO_ROOT}/scripts/compose-wasmtime.sh" "${echo_component}" "${composed}"
            ;;
        secure-defaults)
            composed="${ARTIFACT_ROOT}/composed/e2e-secure-defaults.wasm"
            bash "${REPO_ROOT}/scripts/compose-secure-defaults.sh" "${echo_component}" "${composed}"
            ;;
        *)
            echo "error: unknown E2E_MIDDLEWARE_PROFILE: ${profile}" >&2
            exit 1
            ;;
    esac
fi

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-wasmtime.XXXXXX")"
policy_pid=""
app_pid=""
cleanup() {
    [[ -n "${app_pid}" ]] && kill "${app_pid}" >/dev/null 2>&1 || true
    [[ -n "${policy_pid}" ]] && kill "${policy_pid}" >/dev/null 2>&1 || true
    wait "${app_pid}" >/dev/null 2>&1 || true
    wait "${policy_pid}" >/dev/null 2>&1 || true
    rm -rf "${temporary_directory}"
}
trap cleanup EXIT

"${wasmtime_bin}" serve \
    -W component-model-async=y \
    -S p3=y \
    -S cli=y \
    -S http=y \
    --addr "${policy_address}" \
    "${policy_component}" \
    >"${temporary_directory}/policy.log" 2>&1 &
policy_pid=$!

policy_ready=false
for _ in $(seq 1 100); do
    status="$(curl --silent --max-time 1 --request POST --output /dev/null --write-out '%{http_code}' "${policy_url}" || true)"
    if [[ "${status}" == "401" ]]; then
        policy_ready=true
        break
    fi
    sleep 0.1
done
if [[ "${policy_ready}" != "true" ]]; then
    echo "error: Wasmtime mock policy did not become ready" >&2
    cat "${temporary_directory}/policy.log" >&2
    exit 1
fi

"${wasmtime_bin}" serve \
    -W component-model-async=y \
    -S p3=y \
    -S cli=y \
    -S http=y \
    -S inherit-network=y \
    --env "WASI_MIDDLEWARE_CORS_ORIGINS=https://app.example" \
    --env "WASI_MIDDLEWARE_CORS_METHODS=GET,HEAD,POST" \
    --env "WASI_MIDDLEWARE_CORS_HEADERS=content-type,authorization" \
    --env "WASI_MIDDLEWARE_CORS_ALLOW_CREDENTIALS=false" \
    --env "WASI_MIDDLEWARE_AUTHN_BROKER_URL=${policy_url}" \
    --env "WASI_MIDDLEWARE_AUTHN_TIMEOUT_MS=${authn_timeout_ms}" \
    --env "WASI_MIDDLEWARE_AUTHN_MODE=required" \
    --env "WASI_MIDDLEWARE_SERVICE_ID=echo-service" \
    --env "WASI_MIDDLEWARE_AUTHN_AUDIENCES=api://echo-service" \
    --env "WASI_MIDDLEWARE_AUTHN_MAX_IN_FLIGHT=64" \
    --env "WASI_MIDDLEWARE_AUTHN_ALLOW_INSECURE_LOOPBACK=true" \
    --addr "${app_address}" \
    "${composed}" \
    >"${temporary_directory}/app.log" 2>&1 &
app_pid=$!

ready=false
for _ in $(seq 1 100); do
    status="$(curl --silent --max-time 1 --output /dev/null --write-out '%{http_code}' "http://${app_address}/" || true)"
    if [[ "${status}" != "000" ]]; then
        ready=true
        break
    fi
    sleep 0.1
done
if [[ "${ready}" != "true" ]]; then
    echo "error: Wasmtime E2E service did not become ready" >&2
    cat "${temporary_directory}/policy.log" >&2
    cat "${temporary_directory}/app.log" >&2
    exit 1
fi

stream_failure_repeats="${STREAM_FAILURE_REPEATS:-25}"
immediate_failure_repeats="${IMMEDIATE_FAILURE_REPEATS:-25}"
if ! STREAM_FAILURE_REPEATS="${stream_failure_repeats}" \
    IMMEDIATE_FAILURE_REPEATS="${immediate_failure_repeats}" \
    bash "${REPO_ROOT}/scripts/exercise-http-contract.sh" "http://${app_address}"; then
    cat "${temporary_directory}/policy.log" >&2
    cat "${temporary_directory}/app.log" >&2
    exit 1
fi
assert_logs_do_not_contain_secrets \
    "${temporary_directory}/policy.log" \
    "${temporary_directory}/app.log"
assert_log_occurrences \
    "$((115 + stream_failure_repeats + immediate_failure_repeats))" \
    "wasi-http-middleware-test: terminal-invocation" \
    "${temporary_directory}/app.log"

kill "${app_pid}" >/dev/null 2>&1 || true
wait "${app_pid}" >/dev/null 2>&1 || true
app_pid=""
optional_port=$((app_port + 2))
optional_address="127.0.0.1:${optional_port}"
"${wasmtime_bin}" serve \
    -W component-model-async=y \
    -S p3=y \
    -S cli=y \
    -S http=y \
    -S inherit-network=y \
    --env "WASI_MIDDLEWARE_CORS_ORIGINS=https://app.example" \
    --env "WASI_MIDDLEWARE_CORS_METHODS=GET,HEAD,POST" \
    --env "WASI_MIDDLEWARE_CORS_HEADERS=content-type,authorization" \
    --env "WASI_MIDDLEWARE_CORS_ALLOW_CREDENTIALS=false" \
    --env "WASI_MIDDLEWARE_AUTHN_BROKER_URL=${policy_url}" \
    --env "WASI_MIDDLEWARE_AUTHN_TIMEOUT_MS=${authn_timeout_ms}" \
    --env "WASI_MIDDLEWARE_AUTHN_MODE=optional" \
    --env "WASI_MIDDLEWARE_SERVICE_ID=echo-service" \
    --env "WASI_MIDDLEWARE_AUTHN_AUDIENCES=api://echo-service" \
    --env "WASI_MIDDLEWARE_AUTHN_MAX_IN_FLIGHT=64" \
    --env "WASI_MIDDLEWARE_AUTHN_ALLOW_INSECURE_LOOPBACK=true" \
    --addr "${optional_address}" \
    "${composed}" \
    >"${temporary_directory}/optional.log" 2>&1 &
app_pid=$!

optional_ready=false
for _ in $(seq 1 100); do
    status="$(curl --silent --max-time 1 --output /dev/null --write-out '%{http_code}' "http://${optional_address}/auth-contract" || true)"
    if [[ "${status}" == "200" ]]; then
        optional_ready=true
        break
    fi
    sleep 0.1
done
if [[ "${optional_ready}" != "true" ]]; then
    echo "error: optional-authentication service did not become ready" >&2
    cat "${temporary_directory}/optional.log" >&2
    exit 1
fi

optional_headers="${temporary_directory}/optional-headers"
optional_body="${temporary_directory}/optional-body"
status="$(curl --silent --show-error --max-time 5 \
    --dump-header "${optional_headers}" \
    --output "${optional_body}" \
    --write-out '%{http_code}' \
    "http://${optional_address}/auth-contract")"
if [[ "${status}" != "200" || "$(cat "${optional_body}")" != "anonymous" ]]; then
    echo "error: optional mode did not inject anonymous context" >&2
    cat "${optional_headers}" >&2
    cat "${optional_body}" >&2
    exit 1
fi
if grep -Eiq '^x-wasi-auth-' "${optional_headers}"; then
    echo "error: optional mode exposed trusted request metadata in its response" >&2
    cat "${optional_headers}" >&2
    exit 1
fi
for token_status in "deny:503" "error:503"; do
    token="${token_status%%:*}"
    expected="${token_status##*:}"
    actual="$(curl --silent --show-error --max-time 5 --output /dev/null --write-out '%{http_code}' \
        --header "Authorization: Bearer ${token}" \
        "http://${optional_address}/")"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "error: optional mode downgraded supplied Bearer ${token}: ${actual}" >&2
        exit 1
    fi
done
assert_logs_do_not_contain_secrets \
    "${temporary_directory}/policy.log" \
    "${temporary_directory}/optional.log"

echo "Wasmtime ${wasmtime_version} middleware E2E passed"
