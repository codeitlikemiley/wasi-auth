#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPATIBILITY_FILE="${ROOT_DIR}/compatibility.toml"
GRPC_ENDPOINT="${SPICEDB_GRPC_ENDPOINT:-127.0.0.1:50071}"
HTTP_ENDPOINT="${SPICEDB_HTTP_ENDPOINT:-http://127.0.0.1:18443/v1/permissions/check}"
HTTP_ADDRESS="${HTTP_ENDPOINT#http://}"
HTTP_ADDRESS="${HTTP_ADDRESS%%/*}"
PRESHARED_KEY="${SPICEDB_PRESHARED_KEY:-wasi-authz-live-test-key}"
LOG_FILE="$(mktemp -t wasi-authz-spicedb.XXXXXX.log)"

resolve_tool() {
    override="$1"
    name="$2"
    if [[ -n "${override}" && -x "${override}" ]]; then
        printf '%s\n' "${override}"
        return
    fi
    command -v "${name}" 2>/dev/null || true
}

SPICEDB_BIN="$(resolve_tool "${SPICEDB_BIN:-}" spicedb)"
ZED_BIN="$(resolve_tool "${ZED_BIN:-}" zed)"
if [[ -z "${SPICEDB_BIN}" || -z "${ZED_BIN}" ]]; then
    echo "SpiceDB and zed are required; run 'make provider-tools' or set SPICEDB_BIN and ZED_BIN" >&2
    exit 1
fi
if [[ ! -f "${COMPATIBILITY_FILE}" ]]; then
    echo "missing compatibility.toml tool pins" >&2
    exit 1
fi
EXPECTED_SPICEDB="$(awk -F '"' '/^spicedb[[:space:]]*=/{print $2; exit}' "${COMPATIBILITY_FILE}")"
EXPECTED_ZED="$(awk -F '"' '/^zed[[:space:]]*=/{print $2; exit}' "${COMPATIBILITY_FILE}")"
if [[ -z "${EXPECTED_SPICEDB}" || -z "${EXPECTED_ZED}" ]]; then
    echo "compatibility.toml must define [tools] spicedb and zed pins" >&2
    exit 1
fi
if [[ "$("${SPICEDB_BIN}" version)" != *"spicedb v${EXPECTED_SPICEDB}"* ]]; then
    echo "SpiceDB version does not match compatibility.toml" >&2
    exit 1
fi
if [[ "$("${ZED_BIN}" version 2>/dev/null)" != *"client: zed v${EXPECTED_ZED}"* ]]; then
    echo "zed version does not match compatibility.toml" >&2
    exit 1
fi

cleanup() {
    status=$?
    trap - EXIT
    if [[ -n "${SPICEDB_PID:-}" ]]; then
        kill "${SPICEDB_PID}" 2>/dev/null || true
        wait "${SPICEDB_PID}" 2>/dev/null || true
    fi
    if grep -Fq -- "${PRESHARED_KEY}" "${LOG_FILE}"; then
        echo "SpiceDB emitted the pre-shared key in its logs" >&2
        status=1
    fi
    if [[ ${status} -ne 0 ]]; then
        tail -n 100 "${LOG_FILE}" \
            | PRESHARED_KEY="${PRESHARED_KEY}" perl -pe 's/\Q$ENV{PRESHARED_KEY}\E/[REDACTED]/g' >&2 \
            || true
    fi
    rm -f "${LOG_FILE}"
    exit "${status}"
}
trap cleanup EXIT

zed_cmd() {
    "${ZED_BIN}" \
        --endpoint "${GRPC_ENDPOINT}" \
        --token "${PRESHARED_KEY}" \
        --insecure \
        --skip-version-check \
        "$@"
}

"${ZED_BIN}" validate "${ROOT_DIR}/fixtures/spicedb/relationships.yaml"

"${SPICEDB_BIN}" serve \
    --grpc-addr "${GRPC_ENDPOINT}" \
    --grpc-preshared-key "${PRESHARED_KEY}" \
    --http-enabled \
    --http-addr "${HTTP_ADDRESS}" \
    --metrics-enabled=false \
    --telemetry-endpoint "" \
    --skip-release-check \
    >"${LOG_FILE}" 2>&1 &
SPICEDB_PID=$!

ready=false
for ((attempt = 0; attempt < 100; attempt += 1)); do
    if zed_cmd schema write "${ROOT_DIR}/fixtures/spicedb/schema.zed" >/dev/null 2>&1; then
        ready=true
        break
    fi
    sleep 0.1
done
if [[ "${ready}" != true ]]; then
    echo "SpiceDB did not become ready" >&2
    exit 1
fi

ALICE="v1_aHR0cHM6Ly9pZGVudGl0eS5leGFtcGxlAGFsaWNl"
BOB="v1_aHR0cHM6Ly9pZGVudGl0eS5leGFtcGxlAGJvYg"
CAROL="v1_aHR0cHM6Ly9pZGVudGl0eS5leGFtcGxlAGNhcm9s"
DAVE="v1_aHR0cHM6Ly9pZGVudGl0eS5leGFtcGxlAGRhdmU"
ERIN="v1_aHR0cHM6Ly9pZGVudGl0eS5leGFtcGxlAGVyaW4"
FRANK="v1_aHR0cHM6Ly9pZGVudGl0eS5leGFtcGxlAGZyYW5r"

zed_cmd relationship create group:platform member "user:${CAROL}" >/dev/null
zed_cmd relationship create group:engineering member "user:${BOB}" >/dev/null
zed_cmd relationship create group:engineering member group:platform#member >/dev/null
zed_cmd relationship create tenant:acme member "user:${ALICE}" >/dev/null
zed_cmd relationship create tenant:acme member "user:${DAVE}" >/dev/null
zed_cmd relationship create tenant:acme member "user:${FRANK}" >/dev/null
zed_cmd relationship create tenant:acme member group:engineering#member >/dev/null
zed_cmd relationship create tenant:globex member "user:${ERIN}" >/dev/null
zed_cmd relationship create folder:root tenant tenant:acme >/dev/null
zed_cmd relationship create folder:root viewer group:engineering#member >/dev/null
zed_cmd relationship create folder:root editor "user:${DAVE}" >/dev/null
zed_cmd relationship create folder:child tenant tenant:acme >/dev/null
zed_cmd relationship create folder:child parent folder:root >/dev/null
zed_cmd relationship create document:report-1 tenant tenant:acme >/dev/null
zed_cmd relationship create document:report-1 parent folder:child >/dev/null
zed_cmd relationship create document:report-1 owner "user:${ALICE}" >/dev/null
zed_cmd relationship create document:report-1 editor "user:${BOB}" >/dev/null
zed_cmd relationship create document:report-1 viewer "user:${FRANK}" >/dev/null
zed_cmd relationship create document:globex-report tenant tenant:globex >/dev/null
zed_cmd relationship create document:globex-report owner "user:${ERIN}" >/dev/null
zed_cmd relationship create folder:cycle-a tenant tenant:acme >/dev/null
zed_cmd relationship create folder:cycle-b tenant tenant:acme >/dev/null
zed_cmd relationship create folder:cycle-a parent folder:cycle-b >/dev/null
zed_cmd relationship create folder:cycle-b parent folder:cycle-a >/dev/null

WASI_AUTHZ_SPICEDB_HTTP_ENDPOINT="${HTTP_ENDPOINT}" \
WASI_AUTHZ_SPICEDB_GRPC_ENDPOINT="${GRPC_ENDPOINT}" \
WASI_AUTHZ_SPICEDB_TOKEN="${PRESHARED_KEY}" \
WASI_AUTHZ_ZED="${ZED_BIN}" \
    "${CARGO:-cargo}" test \
        --manifest-path "${ROOT_DIR}/Cargo.toml" \
        -p wasi-authz-spicedb \
        --test live_spicedb \
        -- --ignored --exact live_spicedb_matrix
