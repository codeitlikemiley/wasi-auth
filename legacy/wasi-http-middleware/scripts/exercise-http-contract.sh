#!/usr/bin/env bash

set -euo pipefail

base_url="${1:?usage: exercise-http-contract.sh BASE_URL}"
require_command() {
    command -v "$1" >/dev/null 2>&1 || {
        echo "error: required command not found: $1" >&2
        return 1
    }
}

require_command curl
require_command python3

require_status() {
    local expected="$1"
    shift
    local actual
    actual="$(curl --silent --show-error --max-time 15 --output "${body_file}" --dump-header "${header_file}" --write-out '%{http_code}' --header 'x-wasi-test-count: 1' "$@")"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "error: expected HTTP ${expected}, received ${actual}" >&2
        cat "${header_file}" >&2
        cat "${body_file}" >&2
        return 1
    fi
}

require_header() {
    local name="$1"
    local value_pattern="$2"
    if ! grep -Eiq "^${name}:[[:space:]]*${value_pattern}[[:space:]]*\r?$" "${header_file}"; then
        echo "error: response missing ${name}: ${value_pattern}" >&2
        cat "${header_file}" >&2
        return 1
    fi
}

require_absent_header() {
    local name="$1"
    if grep -Eiq "^${name}:" "${header_file}"; then
        echo "error: response unexpectedly exposed ${name}" >&2
        cat "${header_file}" >&2
        return 1
    fi
}

require_empty_body() {
    if [[ -s "${body_file}" ]]; then
        echo "error: response body was expected to be empty" >&2
        cat "${body_file}" >&2
        return 1
    fi
}

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-contract.XXXXXX")"
trap 'rm -rf "${temporary_directory}"' EXIT
header_file="${temporary_directory}/headers"
body_file="${temporary_directory}/body"

require_status 401 "${base_url}/"
require_header "x-request-id" '[A-Za-z0-9._:/-]{1,128}'
require_header "x-content-type-options" 'nosniff'
require_header "referrer-policy" 'strict-origin-when-cross-origin'

require_status 503 --header 'Authorization: Bearer deny' "${base_url}/"
require_status 503 --header 'Authorization: Bearer error' "${base_url}/"
require_status 503 --header 'Authorization: Bearer malformed' "${base_url}/"
require_status 503 --header 'Authorization: Bearer invalid-identity' "${base_url}/"
require_status 200 --header 'Authorization: Bearer limit-ok' "${base_url}/"
require_status 503 --header 'Authorization: Bearer limit-over' "${base_url}/"

require_status 400 \
    --header 'Authorization: Bearer allow' \
    --header 'Authorization: Bearer deny' \
    "${base_url}/"
oversized_authorization="$(python3 -c 'print("a" * 8193)')"
require_status 400 \
    --header "Authorization: ${oversized_authorization}" \
    "${base_url}/"

require_status 200 \
    --header 'Authorization: Bearer allow' \
    --header 'x-request-id: caller-request-1' \
    "${base_url}/"
require_header "x-request-id" 'caller-request-1'
require_header "x-content-type-options" 'nosniff'
require_header "referrer-policy" 'strict-origin-when-cross-origin'
if [[ "$(cat "${body_file}")" != "echo-service" ]]; then
    echo "error: terminal echo service returned an unexpected body" >&2
    cat "${body_file}" >&2
    exit 1
fi

require_status 200 \
    --request HEAD \
    --header 'Authorization: Bearer allow' \
    "${base_url}/method"
require_header "allow" 'GET, HEAD'
require_empty_body

require_status 405 \
    --request POST \
    --header 'Authorization: Bearer allow' \
    "${base_url}/method"
require_header "allow" 'GET, HEAD'

require_status 413 \
    --header 'Authorization: Bearer allow' \
    "${base_url}/too-large"

require_status 500 \
    --header 'Authorization: Bearer allow' \
    "${base_url}/error"
require_header "x-request-id" '[A-Za-z0-9._:/-]{1,128}'
require_header "x-content-type-options" 'nosniff'
require_header "referrer-policy" 'strict-origin-when-cross-origin'

require_status 200 \
    --header 'Authorization: Bearer allow' \
    --header 'x-wasi-auth-subject: attacker' \
    "${base_url}/identity"
if [[ "$(cat "${body_file}")" != "user-1" ]]; then
    echo "error: spoofed identity was not replaced by policy metadata" >&2
    cat "${body_file}" >&2
    exit 1
fi

require_status 200 \
    --header 'Authorization: Bearer allow' \
    --header 'x-wasi-auth-subject: attacker' \
    --header 'x-wasi-auth-context: attacker' \
    "${base_url}/auth-contract"
if [[ "$(cat "${body_file}")" != "authenticated" ]]; then
    echo "error: terminal did not receive one authenticated V1 context" >&2
    cat "${body_file}" >&2
    exit 1
fi
require_absent_header "x-wasi-auth-context"
require_absent_header "x-wasi-auth-spoofed"

require_status 204 \
    --request OPTIONS \
    --header 'Origin: https://app.example' \
    --header 'Access-Control-Request-Method: POST' \
    --header 'Access-Control-Request-Headers: content-type,authorization' \
    "${base_url}/echo"
require_header "access-control-allow-origin" 'https://app\.example'
require_header "x-content-type-options" 'nosniff'

require_status 403 \
    --header 'Authorization: Bearer allow' \
    --header 'Origin: https://forbidden.example' \
    "${base_url}/"
require_header "vary" 'Origin'
require_header "x-content-type-options" 'nosniff'

require_status 302 \
    --header 'Authorization: Bearer allow' \
    "${base_url}/redirect"
require_header "location" '/'

require_status 404 \
    --header 'Authorization: Bearer allow' \
    "${base_url}/missing"

payload="${temporary_directory}/payload"
echo 'middleware-secret-body-sentinel' >"${payload}"
require_status 200 \
    --request POST \
    --header 'Authorization: Bearer allow' \
    --header 'Cookie: session=middleware-secret-cookie-sentinel' \
    --header 'x-wasi-auth-subject: middleware-secret-identity-sentinel' \
    --data-binary "@${payload}" \
    "${base_url}/echo?middleware-secret-query-sentinel=yes"
cmp "${payload}" "${body_file}" || {
    echo "error: middleware chain changed the streamed body" >&2
    exit 1
}

timing="$(curl --silent --show-error --max-time 5 \
    --output "${body_file}" \
    --dump-header "${header_file}" \
    --write-out '%{http_code} %{time_starttransfer} %{time_total}' \
    --header 'x-wasi-test-count: 1' \
    --header 'Authorization: Bearer allow' \
    "${base_url}/delayed")"
python3 - "${timing}" <<'PY'
import sys

status, first_byte, total = sys.argv[1].split()
first_byte = float(first_byte)
total = float(total)
if status != "200" or total - first_byte < 0.15:
    raise SystemExit(
        f"delayed streaming failed: status={status} first_byte={first_byte} total={total}"
    )
PY
if [[ "$(cat "${body_file}")" != $'first\nsecond' ]]; then
    echo "error: delayed stream body was not preserved" >&2
    cat "${body_file}" >&2
    exit 1
fi

slow_timing="$(curl --silent --show-error --max-time 5 \
    --output "${body_file}" \
    --dump-header "${header_file}" \
    --write-out '%{http_code} %{time_total}' \
    --header 'x-wasi-test-count: 1' \
    --header 'Authorization: Bearer slow' \
    "${base_url}/")"
python3 - "${slow_timing}" <<'PY'
import sys

status, total = sys.argv[1].split()
total = float(total)
if status != "503" or not 1.5 <= total < 3.5:
    raise SystemExit(f"total policy deadline failed: status={status} total={total}")
PY

require_status 200 \
    --http1.1 \
    --header 'Authorization: Bearer allow' \
    "${base_url}/trailers"
if [[ "$(cat "${body_file}")" != "body with trailer" ]]; then
    echo "error: response body associated with trailers was not preserved" >&2
    cat "${body_file}" >&2
    exit 1
fi

for attempt in $(seq 1 "${STREAM_FAILURE_REPEATS:-25}"); do
    set +e
    : >"${body_file}"
    : >"${header_file}"
    failing_status="$(curl --silent --max-time 5 \
        --output "${body_file}" \
        --dump-header "${header_file}" \
        --write-out '%{http_code}' \
        --header 'x-wasi-test-count: 1' \
        --header 'Authorization: Bearer allow' \
        "${base_url}/failing-stream")"
    failing_exit=$?
    set -e
    if [[ "${failing_exit}" == "0" || "${failing_exit}" == "28" ]] \
        || [[ "${failing_status}" != "200" && "${failing_status}" != "000" ]]; then
        echo "error: failing response stream was not surfaced on attempt ${attempt}" >&2
        cat "${header_file}" >&2
        cat "${body_file}" >&2
        exit 1
    fi
    if [[ "${failing_status}" == "200" ]]; then
        if [[ "$(cat "${body_file}")" != "partial body" ]]; then
            echo "error: first response frame was lost before stream failure on attempt ${attempt}" >&2
            cat "${header_file}" >&2
            cat "${body_file}" >&2
            exit 1
        fi
        require_header "x-request-id" '[A-Za-z0-9._:/-]{1,128}'
        require_header "x-content-type-options" 'nosniff'
    fi
done

for attempt in $(seq 1 "${IMMEDIATE_FAILURE_REPEATS:-25}"); do
    set +e
    : >"${body_file}"
    : >"${header_file}"
    immediate_status="$(curl --silent --max-time 5 \
        --output "${body_file}" \
        --dump-header "${header_file}" \
        --write-out '%{http_code}' \
        --header 'x-wasi-test-count: 1' \
        --header 'Authorization: Bearer allow' \
        "${base_url}/immediate-failure")"
    immediate_exit=$?
    set -e
    if [[ "${immediate_exit}" == "0" || "${immediate_exit}" == "28" ]] \
        || [[ "${immediate_status}" != "200" && "${immediate_status}" != "000" ]]; then
        echo "error: immediate response failure was not surfaced on attempt ${attempt}" >&2
        cat "${header_file}" >&2
        cat "${body_file}" >&2
        exit 1
    fi
done

disconnect_payload="${temporary_directory}/disconnect-payload"
python3 - "${disconnect_payload}" <<'PY'
import pathlib
import sys

pathlib.Path(sys.argv[1]).write_bytes(b"x" * (1024 * 1024))
PY
curl --silent --max-time 30 --limit-rate 1024 \
    --request POST \
    --header 'x-wasi-test-count: 1' \
    --header 'Authorization: Bearer allow' \
    --data-binary "@${disconnect_payload}" \
    "${base_url}/echo" >/dev/null 2>&1 &
disconnect_pid=$!
sleep 0.5
kill "${disconnect_pid}" >/dev/null 2>&1 || true
wait "${disconnect_pid}" >/dev/null 2>&1 || true
require_status 200 --header 'Authorization: Bearer allow' "${base_url}/"

statuses="${temporary_directory}/concurrency-statuses"
seq 1 100 | xargs -n 1 -P 20 sh -c \
    'curl --silent --show-error --max-time 15 --output /dev/null --write-out "%{http_code}\n" --header "x-wasi-test-count: 1" --header "Authorization: Bearer allow" "$1/"' \
    _ "${base_url}" >"${statuses}"
if [[ "$(wc -l <"${statuses}" | tr -d ' ')" != "100" ]] \
    || grep -Evq '^200$' "${statuses}"; then
    echo "error: concurrent middleware requests returned unexpected responses" >&2
    sort "${statuses}" | uniq -c >&2
    exit 1
fi

echo "HTTP middleware contract passed for ${base_url}"
