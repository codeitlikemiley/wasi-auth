#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

E2E_MIDDLEWARE_PROFILE=secure-defaults \
E2E_APP_PORT="${E2E_APP_PORT:-19290}" \
E2E_POLICY_PORT="${E2E_POLICY_PORT:-19291}" \
    bash "${REPO_ROOT}/scripts/run-wasmtime-e2e.sh"
