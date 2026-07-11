#!/usr/bin/env python3
"""Normalize cargo-cyclonedx output for reproducible local artifacts."""

from __future__ import annotations

import json
import pathlib
import sys
import uuid
from typing import Any


def normalize(value: Any, repository: str) -> Any:
    """Recursively remove machine-specific repository paths."""
    if isinstance(value, str):
        return value.replace(repository, ".")
    if isinstance(value, list):
        return [normalize(item, repository) for item in value]
    if isinstance(value, dict):
        return {key: normalize(item, repository) for key, item in value.items()}
    return value


def main() -> int:
    if len(sys.argv) != 3:
        print("usage: normalize-sbom.py REPOSITORY SBOM", file=sys.stderr)
        return 2
    repository = str(pathlib.Path(sys.argv[1]).resolve())
    path = pathlib.Path(sys.argv[2])
    document = normalize(json.loads(path.read_text()), repository)
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
