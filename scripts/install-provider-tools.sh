#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

require_command curl
require_command tar
require_command install
os="$(uname -s | tr '[:upper:]' '[:lower:]')"
machine="$(uname -m)"
case "${machine}" in
    x86_64|amd64) arch="amd64" ;;
    arm64|aarch64) arch="arm64" ;;
    *)
        echo "error: unsupported provider-tool architecture: ${machine}" >&2
        exit 1
        ;;
esac
case "${os}" in
    darwin)
        zed_suffix="${os}_${arch}"
        ;;
    linux)
        zed_suffix="${os}_${arch}_gnu"
        ;;
    *)
        echo "error: provider-tool installer supports Linux and macOS only" >&2
        exit 1
        ;;
esac

spicedb_version="$(compat_value spicedb)"
zed_version="$(compat_value zed)"
spicedb_archive="spicedb_${spicedb_version}_${os}_${arch}.tar.gz"
zed_archive="zed_${zed_version}_${zed_suffix}.tar.gz"
spicedb_checksum="$(compat_value "spicedb_${os}_${arch}_sha256")"
zed_checksum="$(compat_value "zed_${os}_${arch}_sha256")"
output="${PROVIDER_TOOL_DIR:-${REPO_ROOT}/target/provider-tools}"
temporary="$(mktemp -d "${TMPDIR:-/tmp}/wasi-authz-tools.XXXXXX")"
trap 'rm -rf "${temporary}"' EXIT
mkdir -p "${output}"

download_and_verify() {
    local repository="$1"
    local version="$2"
    local archive="$3"
    local expected="$4"
    local destination="${temporary}/${archive}"
    curl --fail --location --retry 3 --silent --show-error \
        "https://github.com/authzed/${repository}/releases/download/v${version}/${archive}" \
        --output "${destination}"
    local actual
    actual="$(sha256_file "${destination}" | awk '{print $1}')"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "error: checksum mismatch for ${archive}" >&2
        exit 1
    fi
    mkdir -p "${temporary}/${repository}"
    tar -xzf "${destination}" -C "${temporary}/${repository}"
}

download_and_verify spicedb "${spicedb_version}" "${spicedb_archive}" "${spicedb_checksum}"
download_and_verify zed "${zed_version}" "${zed_archive}" "${zed_checksum}"
install -m 0755 "${temporary}/spicedb/spicedb" "${output}/spicedb"
install -m 0755 "${temporary}/zed/zed" "${output}/zed"
require_version "${output}/spicedb" "${spicedb_version}"
require_version "${output}/zed" "${zed_version}"

echo "installed verified provider tools in ${output}"
