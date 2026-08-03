#!/usr/bin/env python3
"""Generate the machine-readable companion surface manifest.

A downstream consumer such as `leptos_wasi` depends on this repository through
local path dependencies spanning two workspaces at two different versions. The
generated `companion.toml` is the single record of that surface: every crate a
consumer may depend on, every built component, and the release-bundle evidence
paths a consumer pins. It is derived from `cargo metadata`, so a rename, a
version bump, or a dropped crate fails the build instead of silently drifting.
"""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys


SCHEMA = 1

# Crates a downstream consumer is supported in depending on, and the workspace
# each is resolved from. Adding a crate here is a deliberate widening of the
# supported companion surface.
COMPANION_CRATES = [
    ("leptos-wasi-authz", "crates/leptos-wasi-authz", "wasi-auth"),
    ("wasi-authz-cedar", "crates/wasi-authz-cedar", "wasi-auth"),
    ("wasi-authz-client", "crates/wasi-authz-client", "wasi-auth"),
    ("wasi-authz-contract", "crates/wasi-authz-contract", "wasi-auth"),
    ("wasi-authz-spicedb", "crates/wasi-authz-spicedb", "wasi-auth"),
    (
        "wasi-http-authn",
        "legacy/wasi-http-middleware/crates/authn",
        "wasi-http-middleware",
    ),
]

# Built component artifacts. The source directory and the artifact name differ
# for the HTTP PEP on purpose; both names are recorded so a consumer never has
# to infer one from the other.
COMPONENTS = [
    ("authz-http-pep", "wasi-authz-http-pep", "components/http-pep", "http-pep"),
    (
        "cedar-pdp",
        "wasi-authz-cedar-pdp-component",
        "components/cedar-pdp",
        "cedar-pdp",
    ),
    (
        "spicedb-pdp",
        "wasi-authz-spicedb-pdp-component",
        "components/spicedb-pdp",
        "spicedb-pdp",
    ),
]

# Release-bundle evidence: the exact paths `scripts/dry-run-supply-chain.sh`
# writes, relative to the bundle root.
#
# These are deliberately not repository content. `.gitignore` excludes
# `artifacts/RELEASE-SHA256SUMS`, `artifacts/provenance.intoto.json`, and all of
# `reports/supply-chain/`, so none of them resolve in a checkout at any
# revision — a consumer obtains them from the release bundle a run uploads, not
# by pinning a commit. They are recorded here so a consumer knows what to expect
# in that bundle and under which names.
BUNDLE_EVIDENCE = [
    ("checksum_manifest", "artifacts/RELEASE-SHA256SUMS"),
    ("provenance", "artifacts/provenance.intoto.json"),
    ("oci_manifest", "reports/supply-chain/manifest.json"),
    (
        "provenance_signature",
        "reports/supply-chain/provenance.intoto.json.sigstore.json",
    ),
    ("manifest_signature", "reports/supply-chain/manifest.json.sigstore.json"),
    ("signing_key", "reports/supply-chain/cosign.pub"),
]

ARTIFACT_NAME = "wasi-authz"


def metadata(manifest: pathlib.Path) -> dict[str, dict]:
    """Return resolved packages for one workspace, keyed by package name."""
    raw = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version",
            "1",
            "--manifest-path",
            str(manifest),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    return {package["name"]: package for package in json.loads(raw)["packages"]}


def resolve_graph(manifest: pathlib.Path) -> tuple[dict, dict, dict]:
    """Return (packages-by-id, resolve-nodes-by-id, names-by-id) for a workspace.

    Unlike `metadata`, this resolves the dependency graph, which is what the
    path-only closure below is walked from.
    """
    raw = subprocess.run(
        [
            "cargo",
            "metadata",
            "--locked",
            "--format-version",
            "1",
            "--manifest-path",
            str(manifest),
        ],
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    data = json.loads(raw)
    packages = {package["id"]: package for package in data["packages"]}
    nodes = {node["id"]: node for node in data["resolve"]["nodes"]}
    return packages, nodes, {i: p["name"] for i, p in packages.items()}


def local_closure(manifest: pathlib.Path, roots: set[str]) -> set[str]:
    """Return every path-local crate reachable from `roots` in one workspace.

    A crate with no `source` came from a path, not a registry, so it must exist
    in the consumer's checkout for a `--locked` build to resolve. Recording only
    the directly-imported crates under-describes what a consumer actually
    compiles — and some of these leak types through a direct crate's public API,
    so they are part of the observable surface even when never named in a
    consumer manifest.
    """
    packages, nodes, _ = resolve_graph(manifest)
    is_local = {i: p.get("source") is None for i, p in packages.items()}
    seen: set[str] = set()

    def walk(package_id: str) -> None:
        for dependency in nodes.get(package_id, {}).get("deps", []):
            target = dependency["pkg"]
            if not is_local.get(target):
                continue
            name = packages[target]["name"]
            if name in seen:
                continue
            seen.add(name)
            walk(target)

    for package_id, package in packages.items():
        if package["name"] in roots and is_local.get(package_id):
            walk(package_id)
    return seen


def publishable(package: dict) -> bool:
    """Return whether Cargo would allow publishing this package."""
    return package.get("publish") != []


def transitive_lines(repository: pathlib.Path, workspaces: dict) -> list[str]:
    """Emit `[[crate]]` entries for path-local crates reached only indirectly.

    These are not part of the supported surface — a consumer should not name
    them in its own manifest — but they must exist in the checkout for a
    `--locked` build, and at least one of them (`wasi-http-metadata`) has its
    types re-exported through a direct crate's public API. Recording them with
    `direct = false` keeps the distinction explicit rather than leaving the
    closure undescribed.

    Derived, not hardcoded, so a new intermediate crate cannot slip in
    unrecorded.
    """
    direct = {name for name, _, _ in COMPANION_CRATES}
    seen: dict[str, tuple[str, str]] = {}
    for workspace, manifest in (
        ("wasi-auth", repository / "Cargo.toml"),
        (
            "wasi-http-middleware",
            repository / "legacy/wasi-http-middleware/Cargo.toml",
        ),
    ):
        roots = {name for name, _, ws in COMPANION_CRATES if ws == workspace}
        for name in sorted(local_closure(manifest, roots)):
            if name in direct or name in seen:
                continue
            seen[name] = (workspace, manifest)

    lines: list[str] = []
    for name in sorted(seen):
        workspace, _ = seen[name]
        package = workspaces[workspace].get(name)
        if package is None:
            # Reachable from the other workspace's graph; look there instead.
            other = "wasi-auth" if workspace != "wasi-auth" else "wasi-http-middleware"
            package = workspaces[other].get(name)
            workspace = other
        if package is None:
            print(f"error: transitive crate is unresolvable: {name}", file=sys.stderr)
            raise SystemExit(1)
        path = pathlib.Path(package["manifest_path"]).parent.relative_to(repository)
        lines.extend(
            [
                "",
                "[[crate]]",
                "package = " + quote(name),
                "path = " + quote(str(path)),
                "version = " + quote(package["version"]),
                "workspace = " + quote(workspace),
                "publish = " + ("true" if publishable(package) else "false"),
                "direct = false",
            ]
        )
    return lines


def quote(value: str) -> str:
    """Return one TOML basic string."""
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def main() -> int:
    """Write `companion.toml` derived from both workspace manifests."""
    if len(sys.argv) != 3:
        print(
            "usage: generate-companion-manifest.py REPOSITORY OUTPUT",
            file=sys.stderr,
        )
        return 2
    repository = pathlib.Path(sys.argv[1]).resolve()
    output = pathlib.Path(sys.argv[2])

    workspaces = {
        "wasi-auth": metadata(repository / "Cargo.toml"),
        "wasi-http-middleware": metadata(
            repository / "legacy/wasi-http-middleware/Cargo.toml"
        ),
    }

    release = workspaces["wasi-auth"]["wasi-auth"]["version"]

    lines = [
        "# Generated by scripts/generate-companion-manifest.sh. Do not edit by hand.",
        "#",
        "# This is the supported companion surface of this repository: the crates a",
        "# downstream consumer may path-depend on, the components a release builds,",
        "# and the evidence a release bundle carries. Regenerate after any version or",
        "# packaging change; CI requires the tracked copy to match.",
        "#",
        "# Paths under [artifact] other than `components` name files in the release",
        "# bundle, NOT files in this repository. They are git-ignored by design, so",
        "# they do not resolve in a checkout at any revision; a consumer obtains them",
        "# from the bundle a release run uploads. Crate and component paths below are",
        "# repository-relative and do resolve.",
        "#",
        "# `direct = true` marks a crate a consumer is supported in naming in its own",
        "# manifest. `direct = false` marks a path-local crate reached only through",
        "# one of those — never named by a consumer, but required in the checkout for",
        "# a `--locked` build, and in at least one case re-exporting types through a",
        "# direct crate's public API. The indirect set is derived from the resolved",
        "# dependency graph, so a new intermediate crate cannot slip in unrecorded.",
        f"schema = {SCHEMA}",
        "",
        "[release]",
        "name = " + quote("wasi-auth"),
        "version = " + quote(release),
        "",
        "[artifact]",
        "name = " + quote(ARTIFACT_NAME),
        "version = " + quote(release),
        "components = ["
        + ", ".join(quote(component) for component, *_ in COMPONENTS)
        + "]",
    ]
    for key, path in BUNDLE_EVIDENCE:
        lines.append(f"{key} = " + quote(path))

    for name, path, workspace in COMPANION_CRATES:
        packages = workspaces[workspace]
        if name not in packages:
            print(
                f"error: companion crate is missing from {workspace}: {name}",
                file=sys.stderr,
            )
            return 1
        package = packages[name]
        resolved = pathlib.Path(package["manifest_path"]).parent
        expected = repository / path
        if resolved != expected:
            print(
                f"error: companion crate {name} moved: expected {expected}, "
                f"found {resolved}",
                file=sys.stderr,
            )
            return 1
        lines.extend(
            [
                "",
                "[[crate]]",
                "package = " + quote(name),
                "path = " + quote(path),
                "version = " + quote(package["version"]),
                "workspace = " + quote(workspace),
                "publish = " + ("true" if publishable(package) else "false"),
                "direct = true",
            ]
        )

    lines.extend(transitive_lines(repository, workspaces))

    for component, package_name, source_path, wit_stem in COMPONENTS:
        packages = workspaces["wasi-auth"]
        if package_name not in packages:
            print(
                f"error: component package is missing: {package_name}",
                file=sys.stderr,
            )
            return 1
        lines.extend(
            [
                "",
                "[[component]]",
                "component = " + quote(component),
                "package = " + quote(package_name),
                "source_path = " + quote(source_path),
                "path = " + quote(f"components/{component}.wasm"),
                "sbom = " + quote(f"artifacts/sbom/{package_name}.cdx.json"),
                "wit = " + quote(f"reports/wit/{wit_stem}.wit"),
            ]
        )

    output.write_text("\n".join(lines) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
