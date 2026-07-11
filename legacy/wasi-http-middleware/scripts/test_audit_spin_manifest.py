#!/usr/bin/env python3
"""Negative and positive contract tests for the Spin manifest auditor."""

from __future__ import annotations

import importlib.util
import pathlib
import tempfile
import unittest


SCRIPT = pathlib.Path(__file__).with_name("audit-spin-manifest.py")
SPEC = importlib.util.spec_from_file_location("audit_spin_manifest", SCRIPT)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("cannot load Spin manifest auditor")
AUDITOR = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(AUDITOR)


def manifest(*, stack: bool = True, hosts: str | None = None, broker: str | None = None) -> str:
    middleware = """
dependencies.middleware = [
  { component = "request-id" },
  { component = "security-headers" },
  { component = "cors", inherit_configuration = ["environment"] },
  { component = "authn-policy", inherit_configuration = ["environment", "allowed_outbound_hosts"] },
]
""" if stack else ""
    host_list = hosts or '["https://broker.example"]'
    broker_url = broker or "https://broker.example/authenticate"
    return f"""
spin_manifest_version = 2

[[trigger.http]]
route = "/..."
component = "app"
{middleware}
[component.app]
source = "app.wasm"
allowed_outbound_hosts = {host_list}

[component.app.environment]
WASI_MIDDLEWARE_AUTHN_BROKER_URL = "{broker_url}"
WASI_MIDDLEWARE_SERVICE_ID = "app"
WASI_MIDDLEWARE_AUTHN_AUDIENCES = "api://orders"

[component.request-id]
source = "request-id.wasm"
[component.security-headers]
source = "security-headers.wasm"
[component.cors]
source = "cors.wasm"
[component.authn-policy]
source = "authn-policy.wasm"
"""


class AuditTests(unittest.TestCase):
    """Exercise the deployment trust-boundary invariants."""

    def audit(self, contents: str) -> list[str]:
        with tempfile.NamedTemporaryFile("w", suffix=".toml") as fixture:
            fixture.write(contents)
            fixture.flush()
            return AUDITOR.audit(pathlib.Path(fixture.name), [])

    def test_accepts_exact_chain_and_broker_host(self) -> None:
        self.assertEqual(self.audit(manifest()), [])

    def test_accepts_distinct_service_and_oauth_audience(self) -> None:
        self.assertEqual(self.audit(manifest()), [])

    def test_rejects_empty_audience_configuration(self) -> None:
        errors = self.audit(
            manifest().replace(
                'WASI_MIDDLEWARE_AUTHN_AUDIENCES = "api://orders"',
                'WASI_MIDDLEWARE_AUTHN_AUDIENCES = ""',
            )
        )
        self.assertTrue(any("service/audience configuration" in error for error in errors))

    def test_rejects_unwrapped_application(self) -> None:
        self.assertTrue(self.audit(manifest(stack=False)))

    def test_rejects_broad_auth_network_inheritance(self) -> None:
        errors = self.audit(
            manifest(hosts='["https://broker.example", "https://other.example"]')
        )
        self.assertTrue(any("only broker host" in error for error in errors))

    def test_rejects_broker_url_host_mismatch(self) -> None:
        errors = self.audit(manifest(broker="https://other.example/authenticate"))
        self.assertTrue(any("only broker host" in error for error in errors))

    def test_rejects_remote_plain_http(self) -> None:
        errors = self.audit(
            manifest(
                hosts='["http://broker.example"]',
                broker="http://broker.example/authenticate",
            )
        )
        self.assertTrue(any("uses HTTP outside" in error for error in errors))

    def test_accepts_spin_internal_http(self) -> None:
        self.assertEqual(
            self.audit(
                manifest(
                    hosts='["http://authn.spin.internal"]',
                    broker="http://authn.spin.internal/authenticate",
                )
            ),
            [],
        )

    def test_rejects_missing_middleware_source(self) -> None:
        errors = self.audit(manifest().replace('source = "cors.wasm"', ""))
        self.assertTrue(any("has no source" in error for error in errors))


if __name__ == "__main__":
    unittest.main()
