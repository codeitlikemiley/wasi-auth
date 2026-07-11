#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

sibling="${WASI_HTTP_MIDDLEWARE_SOURCE:-${REPO_ROOT}/../wasi-http-middleware}"
expected="$(compat_value wasi_http_middleware_revision)"
if [[ ! -d "${sibling}/.git" ]]; then
    echo "error: unpublished middleware sibling is unavailable: ${sibling}" >&2
    echo "this gate is blocking; clone the sibling at revision ${expected}" >&2
    exit 1
fi
actual="$(git -C "${sibling}" rev-parse HEAD)"
if [[ "${actual}" != "${expected}" ]]; then
    echo "error: middleware sibling revision mismatch" >&2
    echo "expected: ${expected}" >&2
    echo "actual:   ${actual}" >&2
    exit 1
fi
if [[ -n "$(git -C "${sibling}" status --porcelain)" ]]; then
    echo "error: middleware sibling has uncommitted changes" >&2
    exit 1
fi
echo "verified middleware sibling ${actual}"
