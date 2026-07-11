#!/usr/bin/env bash

set -euo pipefail

script_directory="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
exec "${script_directory}/with-spicedb-pdp-wasmtime.sh" \
    "${script_directory}/exercise-spicedb-pdp.sh"
