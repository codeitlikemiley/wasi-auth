#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

wasi_http_version="$(compat_value http)"
wasm_tools_bin="$(resolve_pinned_tool WASM_TOOLS_BIN wasm-tools "$(compat_value wasm_tools)")"
require_file "${AUTHZ_COMPONENT}"

(
    cd "${REPO_ROOT}/wit"
    while read -r checksum path; do
        actual="$(sha256_file "${path}" | awk '{print $1}')"
        if [[ "${actual}" != "${checksum}" ]]; then
            echo "error: vendored WIT checksum mismatch: wit/${path}" >&2
            exit 1
        fi
    done <SHA256SUMS
)

mkdir -p "${REPORT_ROOT}/wit"
report="${REPORT_ROOT}/wit/http-pep.wit"
temporary_report="${report}.tmp"
"${wasm_tools_bin}" validate --features component-model,cm-async "${AUTHZ_COMPONENT}"
"${wasm_tools_bin}" component wit "${AUTHZ_COMPONENT}" >"${temporary_report}"
mv "${temporary_report}" "${report}"

if grep -Fq '0.3.0-rc-' "${report}"; then
    echo "error: component contract still imports a WASI 0.3 release candidate" >&2
    exit 1
fi
grep -Fqx "  import wasi:http/handler@${wasi_http_version};" "${report}" \
    || { echo "error: missing downstream final-WASI HTTP handler import" >&2; exit 1; }
grep -Fqx "  export wasi:http/handler@${wasi_http_version};" "${report}" \
    || { echo "error: missing final-WASI HTTP handler export" >&2; exit 1; }

for required in \
    "wasi:http/client@${wasi_http_version}" \
    "wasi:clocks/monotonic-clock@${wasi_http_version}"; do
    grep -Fqx "  import ${required};" "${report}" \
        || { echo "error: missing required PEP import: ${required}" >&2; exit 1; }
done

forbidden='^[[:space:]]+import (wasi:filesystem/|wasi:keyvalue/|wasi:sockets/|fermyon:spin/(key-value|sqlite|mysql|postgres|redis|mqtt)|spin:(key-value|sqlite|mysql|postgres|redis|mqtt)/)'
if grep -Eq "${forbidden}" "${report}"; then
    grep -E "${forbidden}" "${report}" >&2
    echo "error: HTTP PEP imports a forbidden persistent-data or raw-network capability" >&2
    exit 1
fi

expected_imports="${report}.expected-imports"
actual_imports="${report}.actual-imports"
cat >"${expected_imports}" <<EOF
wasi:cli/environment@0.2.6
wasi:cli/environment@${wasi_http_version}
wasi:cli/exit@0.2.6
wasi:cli/stderr@0.2.6
wasi:clocks/monotonic-clock@${wasi_http_version}
wasi:clocks/types@${wasi_http_version}
wasi:http/client@${wasi_http_version}
wasi:http/handler@${wasi_http_version}
wasi:http/types@${wasi_http_version}
wasi:io/error@0.2.6
wasi:io/streams@0.2.6
wasi:random/insecure-seed@0.2.6
EOF
grep -E '^[[:space:]]+import ' "${report}" \
    | sed -E 's/^[[:space:]]+import //; s/;$//' \
    | LC_ALL=C sort >"${actual_imports}"
LC_ALL=C sort -o "${expected_imports}" "${expected_imports}"
if ! diff -u "${expected_imports}" "${actual_imports}"; then
    rm -f "${expected_imports}" "${actual_imports}"
    echo "error: HTTP PEP imports differ from the exact capability allowlist" >&2
    exit 1
fi
rm -f "${expected_imports}" "${actual_imports}"

handler_edges="$(grep -Ec '^[[:space:]]+(import|export) wasi:http/handler@' "${report}")"
if [[ "${handler_edges}" != "2" ]]; then
    echo "error: expected exactly one HTTP handler import and one export" >&2
    exit 1
fi

cedar_report="${REPORT_ROOT}/wit/cedar-pdp.wit"
cedar_temporary="${cedar_report}.tmp"
require_file "${CEDAR_PDP_COMPONENT}"
"${wasm_tools_bin}" validate --features component-model,cm-async "${CEDAR_PDP_COMPONENT}"
"${wasm_tools_bin}" component wit "${CEDAR_PDP_COMPONENT}" >"${cedar_temporary}"
mv "${cedar_temporary}" "${cedar_report}"
if grep -Fq '0.3.0-rc-' "${cedar_report}"; then
    echo "error: Cedar PDP contract still imports a WASI 0.3 release candidate" >&2
    exit 1
fi
grep -Fqx "  export wasi:http/handler@${wasi_http_version};" "${cedar_report}" \
    || { echo "error: Cedar PDP is missing its final-WASI handler export" >&2; exit 1; }
if grep -Eq '^[[:space:]]+import wasi:http/(handler|client)@' "${cedar_report}"; then
    echo "error: terminal Cedar PDP must not import a downstream handler or HTTP client" >&2
    exit 1
fi
if grep -Eq "${forbidden}" "${cedar_report}"; then
    grep -E "${forbidden}" "${cedar_report}" >&2
    echo "error: Cedar PDP imports a forbidden persistent-data or raw-network capability" >&2
    exit 1
fi

cedar_expected="${cedar_report}.expected-imports"
cedar_actual="${cedar_report}.actual-imports"
cat >"${cedar_expected}" <<EOF
wasi:cli/environment@0.2.6
wasi:cli/environment@${wasi_http_version}
wasi:cli/exit@0.2.6
wasi:cli/stderr@0.2.6
wasi:http/types@${wasi_http_version}
wasi:io/error@0.2.6
wasi:io/streams@0.2.6
wasi:random/insecure-seed@0.2.6
EOF
grep -E '^[[:space:]]+import ' "${cedar_report}" \
    | sed -E 's/^[[:space:]]+import //; s/;$//' \
    | LC_ALL=C sort >"${cedar_actual}"
LC_ALL=C sort -o "${cedar_expected}" "${cedar_expected}"
if ! diff -u "${cedar_expected}" "${cedar_actual}"; then
    rm -f "${cedar_expected}" "${cedar_actual}"
    echo "error: Cedar PDP imports differ from the exact capability allowlist" >&2
    exit 1
fi
rm -f "${cedar_expected}" "${cedar_actual}"

cedar_handler_edges="$(grep -Ec '^[[:space:]]+(import|export) wasi:http/handler@' "${cedar_report}")"
if [[ "${cedar_handler_edges}" != "1" ]]; then
    echo "error: terminal Cedar PDP must have exactly one handler export" >&2
    exit 1
fi

spicedb_report="${REPORT_ROOT}/wit/spicedb-pdp.wit"
spicedb_temporary="${spicedb_report}.tmp"
require_file "${SPICEDB_PDP_COMPONENT}"
"${wasm_tools_bin}" validate --features component-model,cm-async "${SPICEDB_PDP_COMPONENT}"
"${wasm_tools_bin}" component wit "${SPICEDB_PDP_COMPONENT}" >"${spicedb_temporary}"
mv "${spicedb_temporary}" "${spicedb_report}"
if grep -Fq '0.3.0-rc-' "${spicedb_report}"; then
    echo "error: SpiceDB PDP contract still imports a WASI 0.3 release candidate" >&2
    exit 1
fi
grep -Fqx "  export wasi:http/handler@${wasi_http_version};" "${spicedb_report}" \
    || { echo "error: SpiceDB PDP is missing its final-WASI handler export" >&2; exit 1; }
grep -Fqx "  import wasi:http/client@${wasi_http_version};" "${spicedb_report}" \
    || { echo "error: SpiceDB PDP is missing its exact outbound HTTP client import" >&2; exit 1; }
grep -Fqx "  import wasi:clocks/monotonic-clock@${wasi_http_version};" "${spicedb_report}" \
    || { echo "error: SpiceDB PDP is missing its final-WASI deadline clock" >&2; exit 1; }
grep -Fqx "  import wasi:cli/environment@${wasi_http_version};" "${spicedb_report}" \
    || { echo "error: SpiceDB PDP is missing its final-WASI environment import" >&2; exit 1; }
if grep -Eq '^[[:space:]]+import wasi:http/handler@' "${spicedb_report}"; then
    echo "error: terminal SpiceDB PDP must not import a downstream HTTP handler" >&2
    exit 1
fi
if grep -Eq "${forbidden}" "${spicedb_report}"; then
    grep -E "${forbidden}" "${spicedb_report}" >&2
    echo "error: SpiceDB PDP imports a forbidden persistent-data or raw-network capability" >&2
    exit 1
fi

spicedb_expected="${spicedb_report}.expected-imports"
spicedb_actual="${spicedb_report}.actual-imports"
cat >"${spicedb_expected}" <<EOF
wasi:cli/environment@0.2.6
wasi:cli/environment@${wasi_http_version}
wasi:cli/exit@0.2.6
wasi:cli/stderr@0.2.6
wasi:clocks/monotonic-clock@${wasi_http_version}
wasi:clocks/types@${wasi_http_version}
wasi:http/client@${wasi_http_version}
wasi:http/types@${wasi_http_version}
wasi:io/error@0.2.6
wasi:io/streams@0.2.6
wasi:random/insecure-seed@0.2.6
EOF
grep -E '^[[:space:]]+import ' "${spicedb_report}" \
    | sed -E 's/^[[:space:]]+import //; s/;$//' \
    | LC_ALL=C sort >"${spicedb_actual}"
LC_ALL=C sort -o "${spicedb_expected}" "${spicedb_expected}"
if ! diff -u "${spicedb_expected}" "${spicedb_actual}"; then
    rm -f "${spicedb_expected}" "${spicedb_actual}"
    echo "error: SpiceDB PDP imports differ from the exact capability allowlist" >&2
    exit 1
fi
rm -f "${spicedb_expected}" "${spicedb_actual}"

spicedb_handler_edges="$(grep -Ec '^[[:space:]]+(import|export) wasi:http/handler@' "${spicedb_report}")"
if [[ "${spicedb_handler_edges}" != "1" ]]; then
    echo "error: terminal SpiceDB PDP must have exactly one handler export" >&2
    exit 1
fi

echo "validated final-WASI HTTP PEP, Cedar PDP, and SpiceDB PDP component contracts"
