#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

mkdir -p "${ARTIFACT_ROOT}"
temporary="${ARTIFACT_ROOT}/SHA256SUMS.tmp"
: >"${temporary}"

for component in "${COMPONENTS[@]}"; do
    artifact="$(component_file "${component}")"
    require_file "${artifact}"
    digest="$(sha256_file "${artifact}" | awk '{print $1}')"
    printf '%s  components/%s.wasm\n' "${digest}" "${component}" >>"${temporary}"
done

for component in "${CONFORMANCE_COMPONENTS[@]}" "${TEST_COMPONENTS[@]}"; do
    artifact="$(test_component_file "${component}")"
    require_file "${artifact}"
    digest="$(sha256_file "${artifact}" | awk '{print $1}')"
    printf '%s  test-components/%s.wasm\n' "${digest}" "${component}" >>"${temporary}"
done

LC_ALL=C sort "${temporary}" >"${ARTIFACT_ROOT}/SHA256SUMS"
rm -f "${temporary}"

echo "wrote ${ARTIFACT_ROOT}/SHA256SUMS"
