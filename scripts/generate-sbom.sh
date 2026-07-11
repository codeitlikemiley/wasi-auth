#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command cargo
require_command python3
expected="$(compat_value cargo_cyclonedx)"
actual="$(cargo cyclonedx --version 2>&1 || true)"
if [[ "${actual}" != *"${expected}"* ]]; then
    echo "error: cargo-cyclonedx ${expected} is required; found: ${actual:-not installed}" >&2
    exit 1
fi

sibling="${REPO_ROOT}/../wasi-http-middleware"
if [[ ! -d "${sibling}" ]]; then
    echo "error: pinned unpublished sibling is missing: ${sibling}" >&2
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
    rm -f "$(dirname "${manifest}")/${package}.cdx.json"
done

cargo cyclonedx \
    --manifest-path "${REPO_ROOT}/Cargo.toml" \
    --format json \
    --all \
    --target all \
    --spec-version 1.5

list_packages | while IFS=$'\t' read -r package manifest; do
    generated="$(dirname "${manifest}")/${package}.cdx.json"
    if [[ ! -f "${generated}" ]]; then
        echo "error: cargo-cyclonedx did not produce an SBOM for ${package}" >&2
        exit 1
    fi
    destination="${ARTIFACT_ROOT}/sbom/${package}.cdx.json"
    mv "${generated}" "${destination}"
    python3 "${REPO_ROOT}/scripts/normalize-sbom.py" \
        "${REPO_ROOT}" "${sibling}" "${destination}"
done

echo "wrote CycloneDX SBOMs in ${ARTIFACT_ROOT}/sbom"
