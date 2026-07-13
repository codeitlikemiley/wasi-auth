#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command cargo
require_command python3
cyclonedx_version="$(cargo cyclonedx --version 2>&1 || true)"
if [[ "${cyclonedx_version}" != *"0.5.9"* ]]; then
    echo "error: cargo-cyclonedx 0.5.9 is required" >&2
    echo "found: ${cyclonedx_version:-not installed}" >&2
    echo "install it with: cargo install cargo-cyclonedx --locked --version 0.5.9" >&2
    exit 1
fi

mkdir -p "${ARTIFACT_ROOT}/sbom"
rm -f "${ARTIFACT_ROOT}/sbom/"*.cdx.json
metadata="$(cargo metadata --locked --no-deps --format-version 1)"

list_packages() {
    printf '%s' "${metadata}" | python3 -c '
import json
import sys

data = json.load(sys.stdin)
for package in sorted(data["packages"], key=lambda item: item["name"]):
    print("{}\t{}".format(package["name"], package["manifest_path"]))
'
}

list_packages | while IFS=$'\t' read -r package manifest; do
    directory="$(dirname "${manifest}")"
    rm -f "${directory}/${package}.cdx.json"
done

cargo cyclonedx \
    --manifest-path "${REPO_ROOT}/Cargo.toml" \
    --format json \
    --all \
    --target all \
    --spec-version 1.5

list_packages | while IFS=$'\t' read -r package manifest; do
    directory="$(dirname "${manifest}")"
    generated="${directory}/${package}.cdx.json"
    if [[ ! -f "${generated}" ]]; then
        echo "error: cargo-cyclonedx did not produce an SBOM for ${package}" >&2
        exit 1
    fi
    mv "${generated}" "${ARTIFACT_ROOT}/sbom/${package}.cdx.json"
    python3 "${REPO_ROOT}/scripts/normalize-sbom.py" \
        "${REPO_ROOT}" \
        "${ARTIFACT_ROOT}/sbom/${package}.cdx.json"
done

echo "wrote CycloneDX SBOMs in ${ARTIFACT_ROOT}/sbom"
