#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

wac_version="$(compat_value wac)"
wasm_tools_version="$(compat_value wasm_tools)"
wasi_http_version="$(compat_value wasi_http)"
wac_bin="$(resolve_pinned_tool WAC_BIN wac "${wac_version}")"
wasm_tools_bin="$(resolve_pinned_tool WASM_TOOLS_BIN wasm-tools "${wasm_tools_version}")"

terminal="${1:-$(test_component_file echo-service)}"
output="${2:-${ARTIFACT_ROOT}/composed/secure-defaults.wasm}"
middleware="$(component_file secure-defaults)"
require_file "${terminal}"
require_file "${middleware}"
mkdir -p "$(dirname "${output}")"

temporary_directory="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-secure-defaults.XXXXXX")"
temporary="${temporary_directory}/secure-defaults.wasm"
trap 'rm -rf "${temporary_directory}"' EXIT
"${wac_bin}" plug \
    --plug "${terminal}" \
    "${middleware}" \
    --output "${temporary}"

"${wasm_tools_bin}" validate --features component-model,cm-async "${temporary}"
report="${temporary}.wit"
"${wasm_tools_bin}" component wit "${temporary}" >"${report}"
handler="wasi:http/handler@${wasi_http_version}"
grep -Fqx "  export ${handler};" "${report}" || {
    echo "error: fused service does not export ${handler}" >&2
    exit 1
}
if grep -Fqx "  import ${handler};" "${report}"; then
    echo "error: fused service still imports ${handler}" >&2
    exit 1
fi

mv "${temporary}" "${output}"
echo "wrote fused secure-defaults service to ${output}"
