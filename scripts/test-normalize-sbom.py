#!/usr/bin/env python3
"""Regression tests for reproducible CycloneDX normalization."""

from __future__ import annotations

import json
import pathlib
import subprocess
import sys
import tempfile
import unittest


class NormalizeSbomTests(unittest.TestCase):
    def test_canonicalizes_local_package_and_dependency_references(self) -> None:
        repository = "/checkout/wasi-auth"
        sibling = f"{repository}/legacy/wasi-http-middleware"
        local_ddd = "/checkout/ddd"
        ddd_reference = (
            f"path+file://{local_ddd}#ddd_cqrs_es@0.3.0-rc.1"
        )
        document = {
            "metadata": {
                "timestamp": "2026-07-13T00:00:00Z",
                "component": {
                    "name": "wasi-auth",
                    "version": "0.1.0-rc.1",
                    "bom-ref": (
                        f"path+file://{repository}/crates/wasi-auth#0.1.0-rc.1"
                    ),
                    "purl": (
                        "pkg:cargo/wasi-auth@0.1.0-rc.1"
                        f"?download_url=file://{repository}"
                    ),
                },
            },
            "components": [
                {
                    "name": "ddd_cqrs_es",
                    "version": "0.3.0-rc.1",
                    "bom-ref": ddd_reference,
                    "purl": (
                        "pkg:cargo/ddd_cqrs_es@0.3.0-rc.1"
                        f"?download_url=file://{local_ddd}"
                    ),
                }
            ],
            "dependencies": [
                {
                    "ref": "pkg:cargo/wasi-auth@0.1.0-rc.1",
                    "dependsOn": [ddd_reference],
                },
                {"ref": ddd_reference, "dependsOn": []},
            ],
        }

        with tempfile.TemporaryDirectory() as temporary:
            output = pathlib.Path(temporary) / "wasi-auth.cdx.json"
            output.write_text(json.dumps(document))
            subprocess.run(
                [
                    sys.executable,
                    str(pathlib.Path(__file__).with_name("normalize-sbom.py")),
                    repository,
                    sibling,
                    str(output),
                ],
                check=True,
            )
            normalized = json.loads(output.read_text())

        encoded = json.dumps(normalized)
        self.assertNotIn("/checkout", encoded)
        self.assertNotIn("download_url=file:", encoded)
        self.assertNotIn("timestamp", normalized["metadata"])
        self.assertEqual(
            normalized["metadata"]["component"]["bom-ref"],
            "pkg:cargo/wasi-auth@0.1.0-rc.1",
        )
        self.assertEqual(
            normalized["components"][0]["bom-ref"],
            "pkg:cargo/ddd_cqrs_es@0.3.0-rc.1",
        )
        self.assertEqual(
            normalized["dependencies"][0]["dependsOn"],
            ["pkg:cargo/ddd_cqrs_es@0.3.0-rc.1"],
        )
        self.assertEqual(
            normalized["dependencies"][1]["ref"],
            "pkg:cargo/ddd_cqrs_es@0.3.0-rc.1",
        )


if __name__ == "__main__":
    unittest.main()
