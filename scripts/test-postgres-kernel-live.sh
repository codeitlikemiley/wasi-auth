#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command cargo

if [[ -z "${WASI_AUTH_POSTGRES_TEST_URL:-}" ]]; then
    echo "error: WASI_AUTH_POSTGRES_TEST_URL is required" >&2
    exit 1
fi
if [[ -z "${DDD_CQRS_ES_SOURCE:-}" ]]; then
    echo "error: DDD_CQRS_ES_SOURCE is required until the 0.3 release is on crates.io" >&2
    exit 1
fi

ddd_source="$(cd "${DDD_CQRS_ES_SOURCE}" && pwd)"
if [[ ! -f "${ddd_source}/Cargo.toml" ]]; then
    echo "error: DDD_CQRS_ES_SOURCE does not contain Cargo.toml: ${ddd_source}" >&2
    exit 1
fi

cargo_command=(
    cargo
    --config
    "patch.crates-io.ddd_cqrs_es.path='${ddd_source}'"
)

cd "${REPO_ROOT}"
export DATABASE_URL="${WASI_AUTH_POSTGRES_TEST_URL}"
export WASI_AUTH_TEST_POSTGRES_URL="${WASI_AUTH_POSTGRES_TEST_URL}"

"${cargo_command[@]}" run --locked --package wasi-auth-migrate -- apply
"${cargo_command[@]}" test --locked --package wasi-auth --all-features \
    --test postgres_kernel -- --ignored --test-threads=1
"${cargo_command[@]}" test --locked --package wasi-auth --all-features --lib \
    postgres::native::tests::transactional_notification_advances_authorization_epoch \
    -- --exact --ignored --test-threads=1
"${cargo_command[@]}" run --locked --package wasi-auth-migrate -- verify-database

echo "live PostgreSQL relational-kernel contracts passed"
