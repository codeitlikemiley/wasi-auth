#!/usr/bin/env bash

set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "${ROOT}"
VERSION="$(sed -nE 's/^version[[:space:]]*=[[:space:]]*"([^"]+)"/\1/p' Cargo.toml | head -n 1)"
[[ -n "${VERSION}" ]]

metadata="$(mktemp "${TMPDIR:-/tmp}/wasi-http-packages.XXXXXX")"
trap 'rm -f "${metadata}"' EXIT
cargo metadata --locked --no-deps --format-version 1 >"${metadata}"

python3 - "${metadata}" <<'PY'
import json
import sys

document = json.load(open(sys.argv[1], encoding="utf-8"))
publishable = {
    "wasi-http-authn",
    "wasi-http-metadata",
    "wasi-http-middleware-component-support",
    "wasi-http-policy-core",
}
for package in document["packages"]:
    actual = package["publish"] is None
    expected = package["name"] in publishable
    if actual != expected:
        raise SystemExit(
            f"publishability drift for {package['name']}: "
            f"expected publishable={expected}, found {package['publish']}"
        )
PY

expected_files=$'.cargo_vcs_info.json\nCargo.lock\nCargo.toml\nCargo.toml.orig\nREADME.md\nsrc/lib.rs'
packages=(
    wasi-http-authn
    wasi-http-metadata
    wasi-http-middleware-component-support
    wasi-http-policy-core
)

for package in "${packages[@]}"; do
    actual="$(cargo package --locked --allow-dirty --list -p "${package}" | LC_ALL=C sort)"
    [[ "${actual}" == "${expected_files}" ]] || {
        echo "unexpected package file list for ${package}" >&2
        diff -u <(printf '%s\n' "${expected_files}") <(printf '%s\n' "${actual}") >&2 || true
        exit 1
    }
done

# These two crates have no unpublished workspace dependency and must verify
# directly from their generated registry archives.
cargo package --locked --allow-dirty -p wasi-http-metadata
cargo package --locked --allow-dirty -p wasi-http-middleware-component-support

# authn depends on metadata and policy-core in the same unpublished release
# train. Its exact file list was checked above; full archive verification occurs
# after those dependencies are published in the separate release action.
authn_log="$(mktemp "${TMPDIR:-/tmp}/wasi-http-authn-package.XXXXXX")"
if cargo package --locked --allow-dirty -p wasi-http-authn >"${authn_log}" 2>&1; then
    echo "authn registry dependencies are available; full verification passed"
else
    grep -Eq 'no matching package named `(wasi-http-metadata|wasi-http-policy-core)` found' "${authn_log}" || {
        cat "${authn_log}" >&2
        rm -f "${authn_log}"
        echo "authn packaging failed for an unexpected reason" >&2
        exit 1
    }
    echo "authn verification is blocked until its ${VERSION} dependencies are published"
fi
rm -f "${authn_log}"

# policy-core depends on the exact metadata alpha. Before the separate publish
# action places metadata in the registry, verification must fail for that one
# reason. The no-verify archive is still structurally inspected below.
policy_log="$(mktemp "${TMPDIR:-/tmp}/wasi-http-policy-package.XXXXXX")"
policy_archive_available=0
if cargo package --locked --allow-dirty -p wasi-http-policy-core >"${policy_log}" 2>&1; then
    policy_archive_available=1
    echo "policy-core registry dependency is available; full verification passed"
else
    grep -Fq 'no matching package named `wasi-http-metadata` found' "${policy_log}" || {
        cat "${policy_log}" >&2
        rm -f "${policy_log}"
        echo "policy-core packaging failed for an unexpected reason" >&2
        exit 1
    }
    echo "policy-core verification is blocked until wasi-http-metadata ${VERSION} is published"
fi
rm -f "${policy_log}"

POLICY_ARCHIVE_AVAILABLE="${policy_archive_available}" VERSION="${VERSION}" python3 - <<'PY'
import os
import pathlib
import tarfile
import tomllib

root = pathlib.Path("target/package")
version = os.environ["VERSION"]
packages = [
    "wasi-http-metadata",
    "wasi-http-middleware-component-support",
]
if os.environ["POLICY_ARCHIVE_AVAILABLE"] == "1":
    packages.append("wasi-http-policy-core")
expected = {
    ".cargo_vcs_info.json",
    "Cargo.lock",
    "Cargo.toml",
    "Cargo.toml.orig",
    "README.md",
    "src/lib.rs",
}
for package in packages:
    archive = root / f"{package}-{version}.crate"
    if not archive.is_file():
        raise SystemExit(f"missing package archive: {archive}")
    prefix = f"{package}-{version}/"
    with tarfile.open(archive, "r:gz") as source:
        members = {
            member.name.removeprefix(prefix)
            for member in source.getmembers()
            if member.isfile()
        }
        if members != expected:
            raise SystemExit(f"archive content drift for {package}: {sorted(members)}")
        manifest_file = source.extractfile(prefix + "Cargo.toml")
        if manifest_file is None:
            raise SystemExit(f"missing normalized manifest for {package}")
        manifest = tomllib.loads(manifest_file.read().decode())
    for dependency, specification in manifest.get("dependencies", {}).items():
        if isinstance(specification, dict) and "path" in specification:
            raise SystemExit(f"packaged path dependency in {package}: {dependency}")
    if package == "wasi-http-policy-core":
        dependency = manifest["dependencies"]["wasi-http-metadata"]
        if dependency["version"] != f"={version}":
            raise SystemExit("packaged policy-core metadata dependency is not exactly pinned")

with pathlib.Path("crates/policy-core/Cargo.toml").open("rb") as source:
    policy = tomllib.load(source)
with pathlib.Path("Cargo.toml").open("rb") as source:
    workspace = tomllib.load(source)
dependency = workspace["workspace"]["dependencies"]["wasi-http-metadata"]
if dependency["version"] != f"={version}":
    raise SystemExit("policy-core metadata dependency is not exactly pinned")
if policy["package"].get("readme") != "../../README.md":
    raise SystemExit("policy-core package is missing its README")
PY

echo "verified publishable package lists and registry archives"
