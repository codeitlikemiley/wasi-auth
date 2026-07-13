#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

wasmtime_bin="$(resolve_pinned_tool WASMTIME_BIN wasmtime "$(compat_value wasmtime)")"
wac_bin="$(resolve_pinned_tool WAC_BIN wac "$(compat_value wac)")"
require_version oha "$(compat_value oha)"
require_command curl
require_command python3

bash "${REPO_ROOT}/scripts/build-components.sh"

benchmark_artifacts="${ARTIFACT_ROOT}/performance"
report_directory="${REPORT_ROOT}/performance"
mkdir -p "${benchmark_artifacts}" "${report_directory}"
rm -f "${report_directory}/wasmtime-"*.json

terminal="$(test_component_file echo-service)"
cp "${terminal}" "${benchmark_artifacts}/baseline.wasm"
"${wac_bin}" plug --plug "${terminal}" "$(test_component_file passthrough)" \
    --output "${benchmark_artifacts}/passthrough.wasm"
"${wac_bin}" plug --plug "${terminal}" "$(component_file request-id)" \
    --output "${benchmark_artifacts}/request-id.wasm"
"${wac_bin}" plug --plug "${terminal}" "$(component_file security-headers)" \
    --output "${benchmark_artifacts}/security-headers.wasm"

port="${BENCHMARK_PORT:-19200}"
address="127.0.0.1:${port}"
server_pid=""
temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-benchmark.XXXXXX")"
cleanup() {
    [[ -n "${server_pid}" ]] && kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    rm -rf "${temporary_directory}"
}
trap cleanup EXIT

measure() {
    local profile="$1"
    local run="$2"
    local artifact="${benchmark_artifacts}/${profile}.wasm"
    local log="${temporary_directory}/${profile}-${run}.log"

    "${wasmtime_bin}" serve \
        -W component-model-async=y \
        -S p3=y \
        -S cli=y \
        -S http=y \
        --addr "${address}" \
        "${artifact}" >"${log}" 2>&1 &
    server_pid=$!
    local ready=false
    for _ in $(seq 1 100); do
        if curl --silent --max-time 1 "http://${address}/" >/dev/null; then
            ready=true
            break
        fi
        sleep 0.05
    done
    if [[ "${ready}" != "true" ]]; then
        cat "${log}" >&2
        return 1
    fi

    NO_COLOR=false oha -n 2000 -c 100 --no-tui --output-format quiet \
        "http://${address}/"
    NO_COLOR=false oha -n "${BENCHMARK_REQUESTS:-20000}" -c "${BENCHMARK_CONCURRENCY:-100}" \
        --no-tui \
        --output-format json \
        --output "${report_directory}/wasmtime-${profile}-${run}.json" \
        "http://${address}/"

    kill "${server_pid}" >/dev/null 2>&1 || true
    wait "${server_pid}" >/dev/null 2>&1 || true
    server_pid=""
}

for run in 1 2 3; do
    for profile in baseline passthrough request-id security-headers; do
        measure "${profile}" "${run}"
    done
done

python3 "${REPO_ROOT}/scripts/check-performance.py" "${report_directory}"
