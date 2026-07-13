#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

middleware="${REPO_ROOT}/legacy/wasi-http-middleware"
expected="$(compat_value wasi_http_middleware_revision)"
if [[ ! -f "${middleware}/Cargo.toml" ]]; then
    echo "error: imported middleware source is unavailable: ${middleware}" >&2
    exit 1
fi
if ! git -C "${REPO_ROOT}" merge-base --is-ancestor "${expected}" HEAD; then
    echo "error: imported middleware history is missing its pinned revision" >&2
    echo "expected: ${expected}" >&2
    exit 1
fi
echo "verified imported middleware revision ${expected}"
