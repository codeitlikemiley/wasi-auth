#!/usr/bin/env python3
"""Generate a deterministic in-toto statement for local alpha artifacts."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys


def digest(path: pathlib.Path) -> str:
    """Return one SHA-256 digest."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    if len(sys.argv) != 6:
        print(
            "usage: generate-provenance.py REPOSITORY VERSION REVISION SHA256SUMS OUTPUT",
            file=sys.stderr,
        )
        return 2
    repository = pathlib.Path(sys.argv[1])
    version = sys.argv[2]
    revision = sys.argv[3]
    checksums = pathlib.Path(sys.argv[4])
    output = pathlib.Path(sys.argv[5])
    subjects = []
    for line in checksums.read_text().splitlines():
        checksum, name = line.split(maxsplit=1)
        subjects.append({"name": name, "digest": {"sha256": checksum}})
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": sorted(subjects, key=lambda item: item["name"]),
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/codeitlikemiley/wasi-http-middleware/build/v1",
                "externalParameters": {"version": version},
                "internalParameters": {},
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/codeitlikemiley/wasi-http-middleware",
                        "digest": {"gitCommit": revision},
                    },
                    {
                        "uri": "file:Cargo.lock",
                        "digest": {"sha256": digest(repository / "Cargo.lock")},
                    },
                ],
            },
            "runDetails": {
                "builder": {"id": "https://github.com/codeitlikemiley/wasi-http-middleware/local"},
                "metadata": {"invocationId": revision},
                "byproducts": [],
            },
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(statement, indent=2, sort_keys=True) + "\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
