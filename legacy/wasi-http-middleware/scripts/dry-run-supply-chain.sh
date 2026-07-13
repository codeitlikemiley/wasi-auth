#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command git
cosign_bin="$(resolve_pinned_tool COSIGN_BIN cosign "$(compat_value cosign)")"
oras_bin="$(resolve_pinned_tool ORAS_BIN oras "$(compat_value oras)")"
version="$(compat_value version)"
created="$(git -C "${REPO_ROOT}" show -s --format=%cI HEAD)"
output_root="${SUPPLY_CHAIN_OUTPUT:-${REPORT_ROOT}/supply-chain}"
layout="${output_root}/oci-layout"
provenance="${ARTIFACT_ROOT}/provenance.intoto.json"
require_file "${ARTIFACT_ROOT}/SHA256SUMS"

(
    cd "${ARTIFACT_ROOT}"
    while read -r checksum path; do
        actual="$(sha256_file "${path}" | awk '{print $1}')"
        if [[ "${actual}" != "${checksum}" ]]; then
            echo "error: checksum mismatch before OCI packaging: ${path}" >&2
            exit 1
        fi
    done <SHA256SUMS
)

bash "${REPO_ROOT}/scripts/generate-provenance.sh" "${provenance}"
rm -rf "${output_root}"
mkdir -p "${output_root}"

layers=()
while read -r _checksum path; do
    layers+=("${path}:application/wasm")
done <"${ARTIFACT_ROOT}/SHA256SUMS"
layers+=("SHA256SUMS:text/plain")
layers+=("provenance.intoto.json:application/vnd.in-toto+json")
for sbom in "${ARTIFACT_ROOT}/sbom/"*.cdx.json; do
    layers+=("sbom/$(basename "${sbom}"):application/vnd.cyclonedx+json")
done

(
    cd "${ARTIFACT_ROOT}"
    "${oras_bin}" push \
        --oci-layout "${layout}:${version}" \
        --artifact-type application/vnd.wasi.middleware.bundle.v1 \
        --annotation "org.opencontainers.image.created=${created}" \
        "${layers[@]}"
)
"${oras_bin}" manifest fetch --oci-layout "${layout}:${version}" \
    >"${output_root}/manifest.json"

temporary_keys="$(mktemp -d "${TMPDIR:-/tmp}/wasi-http-cosign.XXXXXX")"
trap 'rm -rf "${temporary_keys}"' EXIT
COSIGN_PASSWORD="" "${cosign_bin}" generate-key-pair \
    --output-key-prefix "${temporary_keys}/cosign" >/dev/null
COSIGN_PASSWORD="" "${cosign_bin}" sign-blob --yes \
    --key "${temporary_keys}/cosign.key" \
    --bundle "${output_root}/provenance.sigstore.json" \
    "${provenance}" >/dev/null
"${cosign_bin}" verify-blob \
    --key "${temporary_keys}/cosign.pub" \
    --bundle "${output_root}/provenance.sigstore.json" \
    --insecure-ignore-tlog \
    "${provenance}" >/dev/null
COSIGN_PASSWORD="" "${cosign_bin}" sign-blob --yes \
    --key "${temporary_keys}/cosign.key" \
    --bundle "${output_root}/manifest.sigstore.json" \
    "${output_root}/manifest.json" >/dev/null
"${cosign_bin}" verify-blob \
    --key "${temporary_keys}/cosign.pub" \
    --bundle "${output_root}/manifest.sigstore.json" \
    --insecure-ignore-tlog \
    "${output_root}/manifest.json" >/dev/null
cp "${temporary_keys}/cosign.pub" "${output_root}/cosign.pub"

echo "local OCI layout and verified signature are in ${output_root}"
echo "no registry push was performed"
