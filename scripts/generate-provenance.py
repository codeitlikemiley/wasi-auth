#!/usr/bin/env python3
"""Generate deterministic SLSA/in-toto provenance for local release artifacts."""

from __future__ import annotations

import hashlib
import json
import pathlib
import sys


def digest(path: pathlib.Path) -> str:
    """Return the SHA-256 digest for one file."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> int:
    """Write one deterministic in-toto statement."""
    if len(sys.argv) != 7:
        print(
            "usage: generate-provenance.py REPOSITORY VERSION REVISION "
            "SHA256SUMS WIT_REPORT_DIRECTORY OUTPUT",
            file=sys.stderr,
        )
        return 2
    repository = pathlib.Path(sys.argv[1])
    version = sys.argv[2]
    revision = sys.argv[3]
    checksums = pathlib.Path(sys.argv[4])
    wit_report_directory = pathlib.Path(sys.argv[5])
    output = pathlib.Path(sys.argv[6])
    subjects = []
    for line in checksums.read_text().splitlines():
        checksum, name = line.split(maxsplit=1)
        subjects.append({"name": name, "digest": {"sha256": checksum}})
    for wit_report in sorted(wit_report_directory.glob("*.wit")):
        subjects.append(
            {
                "name": f"reports/wit/{wit_report.name}",
                "digest": {"sha256": digest(wit_report)},
            }
        )
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": sorted(subjects, key=lambda item: item["name"]),
        "predicateType": "https://slsa.dev/provenance/v1",
        "predicate": {
            "buildDefinition": {
                "buildType": "https://github.com/codeitlikemiley/wasi-auth/build/v1",
                "externalParameters": {"version": version},
                "internalParameters": {},
                "resolvedDependencies": [
                    {
                        "uri": "git+https://github.com/codeitlikemiley/wasi-auth",
                        "digest": {"gitCommit": revision},
                    },
                    {
                        "uri": "file:Cargo.lock",
                        "digest": {"sha256": digest(repository / "Cargo.lock")},
                    },
                    {
                        "uri": "file:compatibility.toml",
                        "digest": {"sha256": digest(repository / "compatibility.toml")},
                    },
                    {
                        "uri": "file:wit/SHA256SUMS",
                        "digest": {"sha256": digest(repository / "wit/SHA256SUMS")},
                    },
                ],
            },
            "runDetails": {
                "builder": {"id": "https://github.com/codeitlikemiley/wasi-auth/local"},
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
