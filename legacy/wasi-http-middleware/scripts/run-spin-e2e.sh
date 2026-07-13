#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

profile="${SPIN_COMPAT_PROFILE:-stable-final}"
spin_bin="${SPIN_BIN:-spin}"
require_command "${spin_bin}"
spin_version="$("${spin_bin}" --version 2>&1)"
expected_success=false
expected_status="200"
expected_error=""

python3 "${REPO_ROOT}/scripts/check-spin-fixtures.py"
bash "${REPO_ROOT}/scripts/build-components.sh"

case "${profile}" in
    stable-final)
        expected_version="$(compat_value spin_stable)"
        manifest="${REPO_ROOT}/fixtures/spin/composed-final/spin.toml"
        expected_error='wasi:http/types@0\.3\.0|resource implementation is missing|failed to instantiate'
        bash "${REPO_ROOT}/scripts/compose-wasmtime.sh" \
            "$(test_component_file echo-service)" \
            "${ARTIFACT_ROOT}/composed/full-chain.wasm"
        ;;
    main-terminal)
        expected_version="$(compat_value spin_main_revision)"
        expected_version="${expected_version:0:7}"
        manifest="${REPO_ROOT}/fixtures/spin/final-terminal/spin.toml"
        expected_success=true
        ;;
    main-precomposed-default)
        expected_version="$(compat_value spin_main_revision)"
        expected_version="${expected_version:0:7}"
        manifest="${REPO_ROOT}/fixtures/spin/composed-final-optional/spin.toml"
        expected_error='cpu_time_last_entry|called `Option::unwrap\(\)`|worker panicked'
        bash "${REPO_ROOT}/scripts/compose-wasmtime.sh" \
            "$(test_component_file echo-service)" \
            "${ARTIFACT_ROOT}/composed/full-chain.wasm"
        ;;
    main-precomposed-no-cpu)
        expected_version="$(compat_value spin_main_revision)"
        expected_version="${expected_version:0:7}"
        manifest="${REPO_ROOT}/fixtures/spin/composed-final-optional/spin.toml"
        expected_success=true
        bash "${REPO_ROOT}/scripts/compose-wasmtime.sh" \
            "$(test_component_file echo-service)" \
            "${ARTIFACT_ROOT}/composed/full-chain.wasm"
        ;;
    native-middleware)
        revision="$(compat_value spin_middleware_revision)"
        expected_version="${revision:0:7}"
        manifest="${REPO_ROOT}/fixtures/spin/full-chain/spin.toml"
        expected_error='wasi:http/handler@0\.3\.0-rc-2026-03-15|failed to resolve dependencies'
        ;;
    *)
        echo "error: unknown SPIN_COMPAT_PROFILE: ${profile}" >&2
        exit 2
        ;;
esac

if [[ "${spin_version}" != *"${expected_version}"* ]]; then
    echo "SKIP: expected Spin ${expected_version}; found ${spin_version}" >&2
    exit 77
fi

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-spin.XXXXXX")"
spin_pid=""
cleanup() {
    [[ -n "${spin_pid}" ]] && kill "${spin_pid}" >/dev/null 2>&1 || true
    [[ -n "${spin_pid}" ]] && wait "${spin_pid}" >/dev/null 2>&1 || true
    rm -rf "${temporary_directory}"
}
trap cleanup EXIT
rm -rf "$(dirname "${manifest}")/.spin"
port="${E2E_SPIN_PORT:-19100}"

"${spin_bin}" up \
    --file "${manifest}" \
    --listen "127.0.0.1:${port}" \
    >"${temporary_directory}/spin.log" 2>&1 &
spin_pid=$!

if [[ "${expected_success}" == "true" ]]; then
    status="000"
    for _ in $(seq 1 200); do
        if ! kill -0 "${spin_pid}" >/dev/null 2>&1; then
            cat "${temporary_directory}/spin.log" >&2
            echo "error: Spin exited before readiness" >&2
            exit 1
        fi
        status="$(curl --silent --output "${temporary_directory}/body" --write-out '%{http_code}' "http://127.0.0.1:${port}/" || true)"
        [[ "${status}" == "${expected_status}" ]] && break
        sleep 0.05
    done
    [[ "${status}" == "${expected_status}" ]] || {
        cat "${temporary_directory}/spin.log" >&2
        echo "error: expected HTTP ${expected_status}, received ${status}" >&2
        exit 1
    }
    if [[ "${profile}" == main-precomposed-* ]]; then
        curl --silent --dump-header "${temporary_directory}/headers" --output /dev/null "http://127.0.0.1:${port}/"
        grep -Eiq '^x-request-id:' "${temporary_directory}/headers"
        grep -Eiq '^x-content-type-options: nosniff' "${temporary_directory}/headers"
    fi
    assert_logs_do_not_contain_secrets "${temporary_directory}/spin.log"
    echo "Spin compatibility success: ${profile}"
    exit 0
fi

for _ in $(seq 1 100); do
    if ! kill -0 "${spin_pid}" >/dev/null 2>&1; then
        break
    fi
    curl --silent --max-time 1 --output /dev/null "http://127.0.0.1:${port}/" || true
    sleep 0.05
done
kill "${spin_pid}" >/dev/null 2>&1 || true
wait "${spin_pid}" >/dev/null 2>&1 || true
spin_pid=""
grep -Eiq "${expected_error}" "${temporary_directory}/spin.log" || {
    cat "${temporary_directory}/spin.log" >&2
    echo "error: Spin failed for an unexpected reason" >&2
    exit 1
}
assert_logs_do_not_contain_secrets "${temporary_directory}/spin.log"
echo "expected incompatibility confirmed: ${profile}"
