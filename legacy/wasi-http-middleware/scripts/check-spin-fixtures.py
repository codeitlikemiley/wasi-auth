#!/usr/bin/env python3
"""Verify two independent Spin projects reuse isolated middleware artifacts."""

from __future__ import annotations

import pathlib
import tomllib


ROOT = pathlib.Path(__file__).resolve().parent.parent
FULL_PATH = ROOT / "fixtures/spin/full-chain/spin.toml"
PUBLIC_PATH = ROOT / "fixtures/spin/public-stack/spin.toml"
COMPOSED_PATH = ROOT / "fixtures/spin/composed-final/spin.toml"


def load(path: pathlib.Path) -> dict:
    with path.open("rb") as source:
        return tomllib.load(source)


def stack(manifest: dict) -> list[str]:
    entries = manifest["trigger"]["http"][0]["dependencies"]["middleware"]
    return [entry["component"] if isinstance(entry, dict) else entry for entry in entries]


def main() -> int:
    full = load(FULL_PATH)
    public = load(PUBLIC_PATH)
    composed = load(COMPOSED_PATH)
    assert stack(full) == ["request-id", "security-headers", "cors", "authn-policy"]
    assert stack(public) == ["request-id", "security-headers", "cors"]

    full_components = full["component"]
    public_components = public["component"]
    for name in ["application", "request-id", "security-headers", "cors"]:
        assert full_components[name]["source"] == public_components[name]["source"]

    full_environment = full_components["application"]["environment"]
    public_environment = public_components["application"]["environment"]
    assert full_environment["WASI_MIDDLEWARE_CORS_ORIGINS"] == "https://app.example"
    assert public_environment["WASI_MIDDLEWARE_CORS_ORIGINS"] == "https://public.example"
    assert "WASI_MIDDLEWARE_AUTHN_BROKER_URL" in full_environment
    assert "WASI_MIDDLEWARE_AUTHN_BROKER_URL" not in public_environment
    assert full_environment["WASI_MIDDLEWARE_SERVICE_ID"] == "echo-service"
    assert full_environment["WASI_MIDDLEWARE_AUTHN_AUDIENCES"] == "api://echo-service"
    assert full_components["application"]["allowed_outbound_hosts"] == [
        "http://127.0.0.1:19101"
    ]
    assert "allowed_outbound_hosts" not in public_components["application"]
    composed_application = composed["component"]["application"]
    assert composed_application["source"] == "../../../artifacts/composed/full-chain.wasm"
    assert composed_application["environment"] == full_environment
    assert composed_application["allowed_outbound_hosts"] == [
        "http://127.0.0.1:19101"
    ]
    assert "dependencies" not in composed["trigger"]["http"][0]
    print("Spin canary fixtures preserve isolated final-WASI stacks and configuration")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
