#!/usr/bin/env bash

set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ARTIFACT_ROOT="${ARTIFACT_ROOT:-${REPO_ROOT}/artifacts}"
COMPONENT_ARTIFACT_DIR="${ARTIFACT_ROOT}/components"
TEST_COMPONENT_ARTIFACT_DIR="${ARTIFACT_ROOT}/test-components"
REPORT_ROOT="${REPORT_ROOT:-${REPO_ROOT}/reports}"

COMPONENTS=(request-id security-headers cors authn-policy secure-defaults)
CONFORMANCE_COMPONENTS=(passthrough)
TEST_COMPONENTS=(echo-service mock-authn-broker)

compat_value() {
    local key="$1"
    local value
    value="$(sed -nE "s/^${key}[[:space:]]*=[[:space:]]*\"([^\"]+)\".*/\1/p" "${REPO_ROOT}/compatibility.toml" | head -n 1)"
    if [[ -z "${value}" ]]; then
        echo "error: missing compatibility.toml key: ${key}" >&2
        return 1
    fi
    printf '%s\n' "${value}"
}

require_command() {
    local command_name="$1"
    if [[ "${command_name}" == */* ]]; then
        if [[ ! -x "${command_name}" ]]; then
            echo "error: required command is not executable: ${command_name}" >&2
            return 1
        fi
    elif ! command -v "${command_name}" >/dev/null 2>&1; then
        echo "error: required command not found: ${command_name}" >&2
        return 1
    fi
}

resolve_pinned_tool() {
    local environment_name="$1"
    local command_name="$2"
    local expected="$3"
    local configured="${!environment_name:-}"
    local repo_local="${REPO_ROOT}/target/tools/${command_name}-${expected}/${command_name}"
    local legacy_cache="${WASI_HTTP_MIDDLEWARE_TOOL_ROOT:-${HOME}/.cache/leptos-wasi-tools}/${command_name}-${expected}/${command_name}"
    local selected

    if [[ -n "${configured}" ]]; then
        selected="${configured}"
    elif command -v "${command_name}" >/dev/null 2>&1 \
        && version_matches "${command_name}" "${expected}"; then
        selected="${command_name}"
    elif [[ -x "${repo_local}" ]]; then
        selected="${repo_local}"
    elif [[ -x "${legacy_cache}" ]]; then
        selected="${legacy_cache}"
    else
        echo "error: ${command_name} ${expected} is required; install it or set ${environment_name}" >&2
        return 1
    fi
    require_version "${selected}" "${expected}"
    printf '%s\n' "${selected}"
}

version_matches() {
    local command_name="$1"
    local expected="$2"
    local actual
    if actual="$("${command_name}" --version 2>&1)"; then
        :
    elif actual="$("${command_name}" version 2>&1)"; then
        :
    else
        return 1
    fi
    [[ "${actual}" == *"${expected}"* ]]
}

require_version() {
    local command_name="$1"
    local expected="$2"
    local actual
    require_command "${command_name}"
    if actual="$("${command_name}" --version 2>&1)"; then
        :
    elif actual="$("${command_name}" version 2>&1)"; then
        :
    else
        echo "error: could not query ${command_name} version" >&2
        return 1
    fi
    if [[ "${actual}" != *"${expected}"* ]]; then
        echo "error: ${command_name} version mismatch; expected ${expected}, found: ${actual}" >&2
        return 1
    fi
}

component_file() {
    printf '%s/%s.wasm\n' "${COMPONENT_ARTIFACT_DIR}" "$1"
}

test_component_file() {
    printf '%s/%s.wasm\n' "${TEST_COMPONENT_ARTIFACT_DIR}" "$1"
}

require_file() {
    local path="$1"
    if [[ ! -f "${path}" ]]; then
        echo "error: required file is missing: ${path}" >&2
        return 1
    fi
}

sha256_file() {
    local path="$1"
    if command -v sha256sum >/dev/null 2>&1; then
        sha256sum "${path}"
    elif command -v shasum >/dev/null 2>&1; then
        shasum -a 256 "${path}"
    else
        echo "error: sha256sum or shasum is required" >&2
        return 1
    fi
}

assert_logs_do_not_contain_secrets() {
    local files=("$@")
    local sentinels=(
        "Bearer allow"
        "middleware-secret-body-sentinel"
        "middleware-secret-cookie-sentinel"
        "middleware-secret-identity-sentinel"
        "middleware-secret-query-sentinel"
        "middleware-secret-issuer-sentinel"
        "user-1"
    )
    local sentinel
    local file
    for sentinel in "${sentinels[@]}"; do
        for file in "${files[@]}"; do
            if [[ -f "${file}" ]] && grep -Fq -- "${sentinel}" "${file}"; then
                echo "error: sensitive request or identity data appeared in runtime logs" >&2
                echo "file: ${file}" >&2
                return 1
            fi
        done
    done
}

assert_log_occurrences() {
    local expected="$1"
    local pattern="$2"
    shift 2
    local actual=0
    local file
    local count
    for file in "$@"; do
        if [[ -f "${file}" ]]; then
            count="$(grep -Fc -- "${pattern}" "${file}" || true)"
            actual=$((actual + count))
        fi
    done
    if [[ "${actual}" != "${expected}" ]]; then
        echo "error: expected ${expected} log occurrences, found ${actual}: ${pattern}" >&2
        return 1
    fi
}
