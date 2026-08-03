#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_clean_tree
require_command git
cosign_bin="$(resolve_pinned_tool COSIGN_BIN cosign "$(compat_value cosign)")"
oras_bin="$(resolve_pinned_tool ORAS_BIN oras "$(compat_value oras)")"
version="$(compat_value version)"
created="$(git -C "${REPO_ROOT}" show -s --format=%cI HEAD)"
output_root="${SUPPLY_CHAIN_OUTPUT:-${REPORT_ROOT}/supply-chain}"
layout="${output_root}/oci-layout"
provenance="${ARTIFACT_ROOT}/provenance.intoto.json"
bash "${REPO_ROOT}/scripts/assemble-release-checksums.sh" >/dev/null
require_file "${ARTIFACT_ROOT}/RELEASE-SHA256SUMS"
require_file "${REPORT_ROOT}/wit/http-pep.wit"
require_file "${REPORT_ROOT}/wit/cedar-pdp.wit"
require_file "${REPORT_ROOT}/wit/spicedb-pdp.wit"

(
    cd "${ARTIFACT_ROOT}"
    while read -r checksum path; do
        actual="$(sha256_file "${path}" | awk '{print $1}')"
        if [[ "${actual}" != "${checksum}" ]]; then
            echo "error: checksum mismatch before OCI packaging: ${path}" >&2
            exit 1
        fi
    done <RELEASE-SHA256SUMS
)

bash "${REPO_ROOT}/scripts/generate-provenance.sh" "${provenance}"
rm -rf "${output_root}"
mkdir -p "${output_root}"

layers=()
while read -r _checksum path; do
    media_type="application/vnd.wasi.authz.native"
    if [[ "${path}" == *.wasm ]]; then
        media_type="application/wasm"
    fi
    layers+=("${path}:${media_type}")
done <"${ARTIFACT_ROOT}/RELEASE-SHA256SUMS"
layers+=("RELEASE-SHA256SUMS:text/plain")
layers+=("provenance.intoto.json:application/vnd.in-toto+json")
for sbom in "${ARTIFACT_ROOT}/sbom/"*.cdx.json; do
    require_file "${sbom}"
    layers+=("sbom/$(basename "${sbom}"):application/vnd.cyclonedx+json")
done
temporary_wit_files=()
temporary_keys=""
cleanup() {
    if [[ -n "${temporary_keys}" ]]; then
        rm -rf "${temporary_keys}"
    fi
    if ((${#temporary_wit_files[@]} > 0)); then
        rm -f "${temporary_wit_files[@]}"
    fi
}
trap cleanup EXIT
for wit in "${REPORT_ROOT}/wit/"*.wit; do
    destination="${ARTIFACT_ROOT}/$(basename "${wit}")"
    cp "${wit}" "${destination}"
    temporary_wit_files+=("${destination}")
    layers+=("$(basename "${wit}"):application/wit")
done

(
    cd "${ARTIFACT_ROOT}"
    "${oras_bin}" push \
        --oci-layout "${layout}:${version}" \
        --artifact-type application/vnd.wasi.authz.bundle.v1 \
        --annotation "org.opencontainers.image.created=${created}" \
        "${layers[@]}"
)
"${oras_bin}" manifest fetch --oci-layout "${layout}:${version}" \
    >"${output_root}/manifest.json"

temporary_keys="$(mktemp -d "${TMPDIR:-/tmp}/wasi-authz-cosign.XXXXXX")"
COSIGN_PASSWORD="" "${cosign_bin}" generate-key-pair \
    --output-key-prefix "${temporary_keys}/cosign" >/dev/null
# This dry run signs with an ephemeral key and verifies with
# --insecure-ignore-tlog, so it never uses a transparency log, a certificate
# authority, or a timestamp authority. Cosign 3 nevertheless resolves a signing
# config from Sigstore's TUF repository unless one is supplied, which makes an
# otherwise local step fail on any host without egress to that service. Supply
# an explicit config carrying no Fulcio, Rekor, OIDC, or TSA endpoint so the
# assembly and signature-verification proof stays hermetic. A real release does
# not reuse this path; it signs with an authorized identity and publishes
# transparency evidence.
signing_config="${temporary_keys}/signing-config.json"
"${cosign_bin}" signing-config create \
    --no-default-fulcio \
    --no-default-rekor \
    --no-default-oidc \
    --no-default-tsa \
    --out "${signing_config}" >/dev/null
for signed in "${provenance}" "${output_root}/manifest.json"; do
    name="$(basename "${signed}")"
    bundle="${output_root}/${name}.sigstore.json"
    COSIGN_PASSWORD="" "${cosign_bin}" sign-blob --yes \
        --signing-config "${signing_config}" \
        --key "${temporary_keys}/cosign.key" \
        --bundle "${bundle}" "${signed}" >/dev/null
    "${cosign_bin}" verify-blob \
        --key "${temporary_keys}/cosign.pub" \
        --bundle "${bundle}" \
        --insecure-ignore-tlog "${signed}" >/dev/null
done
cp "${temporary_keys}/cosign.pub" "${output_root}/cosign.pub"

echo "local OCI layout and verified signatures are in ${output_root}"
echo "no registry push was performed"
