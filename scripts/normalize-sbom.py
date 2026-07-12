#!/usr/bin/env python3
"""Normalize cargo-cyclonedx output into reproducible workspace artifacts."""

from __future__ import annotations

import json
import pathlib
import sys
import uuid
from typing import Any


def normalize(value: Any, repository: str, sibling: str) -> Any:
    """Remove machine-specific repository paths recursively."""
    if isinstance(value, str):
        return value.replace(repository, ".").replace(sibling, "legacy/wasi-http-middleware")
    if isinstance(value, list):
        return [normalize(item, repository, sibling) for item in value]
    if isinstance(value, dict):
        return {
            key: normalize(item, repository, sibling) for key, item in value.items()
        }
    return value


def canonicalize_local_cargo_references(document: dict[str, Any]) -> dict[str, Any]:
    """Replace machine-local Cargo path identities with package identities.

    cargo-cyclonedx describes patched and workspace dependencies with absolute
    ``file://`` URLs. Those URLs are useful while building, but make a tracked
    release SBOM depend on the checkout location. A Cargo package URL already
    carries the package name and version, so it is the stable release identity.
    """
    replacements: dict[str, str] = {}
    metadata_component = document.get("metadata", {}).get("component")
    components = document.get("components", [])
    candidates = [metadata_component, *components]

    for component in candidates:
        if not isinstance(component, dict):
            continue
        purl = component.get("purl")
        if not isinstance(purl, str) or "download_url=file:" not in purl:
            continue
        canonical_purl = purl.split("?", maxsplit=1)[0]
        old_reference = component.get("bom-ref")
        if isinstance(old_reference, str):
            replacements[old_reference] = canonical_purl
        component["bom-ref"] = canonical_purl
        component["purl"] = canonical_purl

    def replace_references(value: Any) -> Any:
        if isinstance(value, str):
            return replacements.get(value, value)
        if isinstance(value, list):
            return [replace_references(item) for item in value]
        if isinstance(value, dict):
            return {
                key: replace_references(item) for key, item in value.items()
            }
        return value

    return replace_references(document)


def main() -> int:
    """Normalize one CycloneDX JSON document in place."""
    if len(sys.argv) != 4:
        print("usage: normalize-sbom.py REPOSITORY SIBLING SBOM", file=sys.stderr)
        return 2
    repository = str(pathlib.Path(sys.argv[1]).resolve())
    sibling = str(pathlib.Path(sys.argv[2]).resolve())
    path = pathlib.Path(sys.argv[3])
    document = normalize(json.loads(path.read_text()), repository, sibling)
    document = canonicalize_local_cargo_references(document)
    metadata = document.get("metadata", {})
    metadata.pop("timestamp", None)
    component = metadata.get("component", {})
    identity = "{name}@{version}".format(
        name=component.get("name", path.stem),
        version=component.get("version", "unknown"),
    )
    document["serialNumber"] = f"urn:uuid:{uuid.uuid5(uuid.NAMESPACE_URL, identity)}"
    path.write_text(json.dumps(document, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
