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
        return value.replace(repository, ".").replace(sibling, "../wasi-http-middleware")
    if isinstance(value, list):
        return [normalize(item, repository, sibling) for item in value]
    if isinstance(value, dict):
        return {
            key: normalize(item, repository, sibling) for key, item in value.items()
        }
    return value


def main() -> int:
    """Normalize one CycloneDX JSON document in place."""
    if len(sys.argv) != 4:
        print("usage: normalize-sbom.py REPOSITORY SIBLING SBOM", file=sys.stderr)
        return 2
    repository = str(pathlib.Path(sys.argv[1]).resolve())
    sibling = str(pathlib.Path(sys.argv[2]).resolve())
    path = pathlib.Path(sys.argv[3])
    document = normalize(json.loads(path.read_text()), repository, sibling)
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
