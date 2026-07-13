#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command cargo

if [[ -z "${WASI_AUTH_POSTGRES_TEST_URL:-}" ]]; then
    echo "error: WASI_AUTH_POSTGRES_TEST_URL is required" >&2
    exit 1
fi
cd "${REPO_ROOT}"
export DATABASE_URL="${WASI_AUTH_POSTGRES_TEST_URL}"
export WASI_AUTH_TEST_POSTGRES_URL="${WASI_AUTH_POSTGRES_TEST_URL}"

cargo run --locked --package wasi-auth-migrate -- apply
cargo test --locked --package wasi-auth --all-features \
    --test postgres_kernel -- --ignored --test-threads=1
cargo test --locked --package wasi-auth --all-features --lib \
    postgres::native::tests::transactional_notification_advances_authorization_epoch \
    -- --exact --ignored --test-threads=1
cargo run --locked --package wasi-auth-migrate -- verify-database

echo "live PostgreSQL relational-kernel contracts passed"
