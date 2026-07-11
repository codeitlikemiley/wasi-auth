#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

if [[ $# -eq 0 ]]; then
    echo "usage: $0 COMMAND [ARG ...]" >&2
    exit 2
fi

require_command curl
require_command python3
wasmtime_bin="$(resolve_pinned_tool WASMTIME_BIN wasmtime "$(compat_value wasmtime)")"
spicedb_bin="$(resolve_pinned_tool SPICEDB_BIN spicedb "$(compat_value spicedb)")"
zed_bin="$(resolve_pinned_tool ZED_BIN zed "$(compat_value zed)")"
start_compatibility_pdp="${WASI_AUTHZ_START_COMPATIBILITY_PDP:-1}"
[[ "${start_compatibility_pdp}" == "0" || "${start_compatibility_pdp}" == "1" ]] || {
    echo "WASI_AUTHZ_START_COMPATIBILITY_PDP must be 0 or 1" >&2
    exit 2
}
if [[ "${start_compatibility_pdp}" == "1" ]]; then
    require_file "${SPICEDB_PDP_COMPONENT}"
fi

available_port() {
    python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()'
}

grpc_port="$(available_port)"
http_port="$(available_port)"
pdp_port="$(available_port)"
grpc_address="127.0.0.1:${grpc_port}"
spicedb_http_address="127.0.0.1:${http_port}"
spicedb_endpoint="http://${spicedb_http_address}/v1/permissions/check"
pdp_address="127.0.0.1:${pdp_port}"
spicedb_token="spicedb-component-live-secret-0123456789"
pep_token="pep-component-live-secret-0123456789"
allow_issuer="middleware-secret-issuer-sentinel"
allow_subject_name="user-1"
deny_subject_name="user-no-relation"
allow_subject_id="v1_bWlkZGxld2FyZS1zZWNyZXQtaXNzdWVyLXNlbnRpbmVsAHVzZXItMQ"
deep_subject_id="v1_bWlkZGxld2FyZS1zZWNyZXQtaXNzdWVyLXNlbnRpbmVsAHVzZXItZGVlcA"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/wasi-authz-spicedb-pdp.XXXXXX")"
spicedb_log="${temporary}/spicedb.log"
pdp_log="${temporary}/pdp.log"

cleanup() {
    status=$?
    trap - EXIT
    if [[ -n "${pdp_pid:-}" ]]; then
        kill "${pdp_pid}" 2>/dev/null || true
        wait "${pdp_pid}" 2>/dev/null || true
    fi
    if [[ -n "${spicedb_pid:-}" ]]; then
        kill "${spicedb_pid}" 2>/dev/null || true
        wait "${spicedb_pid}" 2>/dev/null || true
    fi
    for sentinel in \
        "${spicedb_token}" \
        "${pep_token}" \
        "${allow_issuer}" \
        "${allow_subject_name}" \
        "${deny_subject_name}" \
        "user-deep" \
        "spicedb-pdp-allow" \
        "spicedb-pdp-deny" \
        "spicedb-pdp-depth-limit"; do
        if grep -Fq -- "${sentinel}" "${spicedb_log}" "${pdp_log}" 2>/dev/null; then
            echo "error: SpiceDB PDP runtime logs disclosed credential or decision data" >&2
            status=1
        fi
    done
    if [[ ${status} -ne 0 ]]; then
        for log in "${spicedb_log}" "${pdp_log}"; do
            if [[ -f "${log}" ]]; then
                PEP_TOKEN="${pep_token}" \
                SPICEDB_TOKEN="${spicedb_token}" \
                    perl -pe '
                        s/\Q$ENV{PEP_TOKEN}\E/[REDACTED]/g;
                        s/\Q$ENV{SPICEDB_TOKEN}\E/[REDACTED]/g;
                    ' "${log}" | tail -n 100 >&2 || true
            fi
        done
    fi
    rm -rf "${temporary}"
    exit "${status}"
}
trap cleanup EXIT

zed_cmd() {
    "${zed_bin}" \
        --endpoint "${grpc_address}" \
        --token "${spicedb_token}" \
        --insecure \
        --skip-version-check \
        "$@"
}

"${spicedb_bin}" serve \
    --log-level "${SPICEDB_LOG_LEVEL:-warn}" \
    --grpc-addr "${grpc_address}" \
    --grpc-preshared-key "${spicedb_token}" \
    --http-enabled \
    --http-addr "${spicedb_http_address}" \
    --metrics-enabled=false \
    --telemetry-endpoint "" \
    --skip-release-check \
    >"${spicedb_log}" 2>&1 &
spicedb_pid=$!

spicedb_ready=false
for ((attempt = 0; attempt < 100; attempt += 1)); do
    if zed_cmd schema write "${REPO_ROOT}/fixtures/spicedb-pdp/schema.zed" >/dev/null 2>&1; then
        spicedb_ready=true
        break
    fi
    sleep 0.1
done
if [[ "${spicedb_ready}" != true ]]; then
    echo "error: SpiceDB 1.54 did not become ready" >&2
    exit 1
fi
zed_cmd relationship create \
    counter:session-counter incrementer "principal:${allow_subject_id}" >/dev/null
zed_cmd relationship create \
    counter:deep-counter incrementer group:depth-0#member >/dev/null
for ((index = 0; index < 59; index += 1)); do
    next=$((index + 1))
    zed_cmd relationship create \
        "group:depth-${index}" member "group:depth-${next}#member" >/dev/null
done
zed_cmd relationship create \
    group:depth-59 member "principal:${deep_subject_id}" >/dev/null

PDP_ARGS=(
    serve \
    -W component-model-async=y \
    -S p3=y \
    -S cli=y \
    -S http=y \
    -S inherit-network=y \
    --addr "${pdp_address}" \
    --env "WASI_AUTHZ_PDP_BEARER_TOKEN=${pep_token}" \
    --env "WASI_AUTHZ_SPICEDB_ENDPOINT=${spicedb_endpoint}" \
    --env "WASI_AUTHZ_SPICEDB_ALLOW_LOOPBACK_DEV=true" \
    --env "WASI_AUTHZ_SPICEDB_BEARER_TOKEN=${spicedb_token}" \
    --env "WASI_AUTHZ_SPICEDB_ACTION_PERMISSION_MAP=counter.increment=increment" \
    --env "WASI_AUTHZ_SPICEDB_POLICY_REVISION=live-schema-1" \
    --env "WASI_AUTHZ_SPICEDB_MODEL_VERSION=spicedb-1.54.0"
)
if [[ -n "${AUTHZEN_PDP_MAX_INSTANCE_REUSE_COUNT:-}" ]]; then
    PDP_ARGS+=(--max-instance-reuse-count "${AUTHZEN_PDP_MAX_INSTANCE_REUSE_COUNT}")
fi
if [[ -n "${AUTHZEN_PDP_MAX_INSTANCE_CONCURRENT_REUSE_COUNT:-}" ]]; then
    PDP_ARGS+=(--max-instance-concurrent-reuse-count "${AUTHZEN_PDP_MAX_INSTANCE_CONCURRENT_REUSE_COUNT}")
fi
if [[ -n "${AUTHZEN_PDP_IDLE_INSTANCE_TIMEOUT:-}" ]]; then
    PDP_ARGS+=(--idle-instance-timeout "${AUTHZEN_PDP_IDLE_INSTANCE_TIMEOUT}")
fi
if [[ "${MIDDLEWARE_DIAGNOSTICS:-0}" == "1" ]]; then
    PDP_ARGS+=(--env "WASI_MIDDLEWARE_DIAGNOSTICS=true")
fi
if [[ "${start_compatibility_pdp}" == "1" ]]; then
    PDP_ARGS+=("${SPICEDB_PDP_COMPONENT}")
    "${wasmtime_bin}" "${PDP_ARGS[@]}" >"${pdp_log}" 2>&1 &
    pdp_pid=$!

    pdp_ready=false
    for ((attempt = 0; attempt < 100; attempt += 1)); do
        status="$(curl --silent --output /dev/null --write-out '%{http_code}' \
            --connect-timeout 1 --max-time 2 \
            --header 'content-type: application/json' \
            --data-binary @"${REPO_ROOT}/fixtures/spicedb-pdp/allow.json" \
            "http://${pdp_address}/access/v1/evaluation" || true)"
        if [[ "${status}" == "401" ]]; then
            pdp_ready=true
            break
        fi
        sleep 0.1
    done
    if [[ "${pdp_ready}" != true ]]; then
        echo "error: final-WASIp3 SpiceDB PDP did not become ready" >&2
        exit 1
    fi
    export WASI_AUTHZ_TEST_PDP_URL="http://${pdp_address}/access/v1/evaluation"
    export WASI_AUTHZ_TEST_PDP_BEARER_TOKEN="${pep_token}"
else
    export WASI_AUTHZ_TEST_PDP_URL=""
    export WASI_AUTHZ_TEST_PDP_BEARER_TOKEN=""
fi
export WASI_AUTHZ_TEST_SPICEDB_URL="${spicedb_endpoint}"
export WASI_AUTHZ_TEST_SPICEDB_TOKEN="${spicedb_token}"
export WASI_AUTHZ_TEST_SPICEDB_POLICY_REVISION="live-schema-1"
export WASI_AUTHZ_TEST_SPICEDB_MODEL_VERSION="spicedb-1.54.0"
export WASI_AUTHZ_TEST_SPICEDB_PID="${spicedb_pid}"
export WASI_AUTHZ_TEST_AUTHZEN_PDP_PID="${pdp_pid:-}"
export WASI_AUTHZ_TEST_ALLOW_ISSUER="${allow_issuer}"
export WASI_AUTHZ_TEST_ALLOW_SUBJECT="${allow_subject_name}"
export WASI_AUTHZ_TEST_DENY_SUBJECT="${deny_subject_name}"
export WASI_AUTHZ_TEST_ACTION="counter.increment"
export WASI_AUTHZ_TEST_RESOURCE_TYPE="counter"
export WASI_AUTHZ_TEST_RESOURCE_ID="session-counter"
if [[ "${start_compatibility_pdp}" == "1" ]]; then
    export WASI_AUTHZ_TEST_PDP_COMPONENT="${SPICEDB_PDP_COMPONENT}"
    export WASI_AUTHZ_TEST_PDP_COMPONENT_SHA256
    WASI_AUTHZ_TEST_PDP_COMPONENT_SHA256="$(sha256_file "${SPICEDB_PDP_COMPONENT}" | awk '{print $1}')"
else
    export WASI_AUTHZ_TEST_PDP_COMPONENT=""
    export WASI_AUTHZ_TEST_PDP_COMPONENT_SHA256=""
fi
export WASI_AUTHZ_TEST_SPICEDB_VERSION="$(compat_value spicedb)"
export WASI_AUTHZ_TEST_WASMTIME_VERSION="$(compat_value wasmtime)"

set +e
"$@"
child_status=$?
set -e
exit "${child_status}"
