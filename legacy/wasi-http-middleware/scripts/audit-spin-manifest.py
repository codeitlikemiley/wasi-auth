#!/usr/bin/env python3
"""Reject HTTP triggers that bypass or misconfigure the middleware chain."""

from __future__ import annotations

import argparse
import fnmatch
import pathlib
import sys
import tomllib
import urllib.parse

EXPECTED = ["request-id", "security-headers", "cors", "authn-policy"]


def component_name(entry: object) -> str | None:
    if isinstance(entry, str):
        return entry
    if isinstance(entry, dict):
        value = entry.get("component")
        return value if isinstance(value, str) else None
    return None


def is_allowed(route: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(route, pattern) for pattern in patterns)


def audit(path: pathlib.Path, allowed_routes: list[str]) -> list[str]:
    with path.open("rb") as source:
        manifest = tomllib.load(source)

    errors: list[str] = []
    triggers = manifest.get("trigger", {}).get("http", [])
    components = manifest.get("component", {})
    if not isinstance(triggers, list) or not triggers:
        return ["manifest has no HTTP triggers"]
    if not isinstance(components, dict):
        return ["manifest component table is invalid"]

    for index, trigger in enumerate(triggers):
        route = trigger.get("route", f"<trigger-{index}>")
        if is_allowed(route, allowed_routes):
            continue
        middleware = trigger.get("dependencies", {}).get("middleware", [])
        actual = [component_name(entry) for entry in middleware]
        if actual != EXPECTED:
            errors.append(
                f"route {route!r} middleware must be {EXPECTED!r}, found {actual!r}"
            )
            continue

        for name in EXPECTED:
            definition = components.get(name)
            if not isinstance(definition, dict) or not isinstance(
                definition.get("source"), str
            ):
                errors.append(
                    f"route {route!r} middleware component {name!r} has no source"
                )

        cors = middleware[2]
        auth = middleware[3]
        if not isinstance(cors, dict) or cors.get("inherit_configuration") != [
            "environment"
        ]:
            errors.append(f"route {route!r} CORS must inherit only environment")
        if not isinstance(auth, dict) or auth.get("inherit_configuration") != [
            "environment",
            "allowed_outbound_hosts",
        ]:
            errors.append(
                f"route {route!r} auth must inherit environment and allowed_outbound_hosts"
            )

        primary_name = trigger.get("component")
        primary = components.get(primary_name) if isinstance(primary_name, str) else None
        if not isinstance(primary, dict):
            errors.append(f"route {route!r} references an unknown primary component")
            continue
        environment = primary.get("environment", {})
        broker_url = environment.get("WASI_MIDDLEWARE_AUTHN_BROKER_URL") if isinstance(environment, dict) else None
        if not isinstance(broker_url, str):
            errors.append(f"route {route!r} has no authentication broker URL")
            continue
        parsed = urllib.parse.urlsplit(broker_url)
        if (
            parsed.scheme not in {"http", "https"}
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.fragment
        ):
            errors.append(f"route {route!r} has an invalid authentication broker URL")
            continue
        try:
            port = parsed.port
        except ValueError:
            errors.append(f"route {route!r} has an invalid authentication broker port")
            continue
        insecure_loopback = environment.get(
            "WASI_MIDDLEWARE_AUTHN_ALLOW_INSECURE_LOOPBACK"
        ) == "true"
        spin_service = parsed.hostname.removesuffix(".spin.internal")
        spin_internal = (
            parsed.hostname.endswith(".spin.internal")
            and bool(spin_service)
            and "." not in spin_service
        )
        loopback = parsed.hostname in {"localhost", "127.0.0.1", "::1"}
        if parsed.scheme == "http" and not (spin_internal or (loopback and insecure_loopback)):
            errors.append(
                f"route {route!r} uses HTTP outside the Spin-internal or explicit loopback exception"
            )
        service_id = environment.get("WASI_MIDDLEWARE_SERVICE_ID")
        audience_value = environment.get("WASI_MIDDLEWARE_AUTHN_AUDIENCES")
        audiences = (
            [audience.strip() for audience in audience_value.split(",")]
            if isinstance(audience_value, str)
            else []
        )
        if (
            not isinstance(service_id, str)
            or not service_id
            or not audiences
            or any(not audience for audience in audiences)
        ):
            errors.append(f"route {route!r} has invalid service/audience configuration")
        host = parsed.hostname
        if ":" in host and not host.startswith("["):
            host = f"[{host}]"
        expected_host = f"{parsed.scheme}://{host}"
        if port is not None:
            expected_host += f":{port}"
        allowed_hosts = primary.get("allowed_outbound_hosts")
        if allowed_hosts != [expected_host]:
            errors.append(
                f"route {route!r} authn must inherit only broker host "
                f"{expected_host!r}, found {allowed_hosts!r}"
            )

    return errors


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("manifest", type=pathlib.Path)
    parser.add_argument(
        "--allow-unwrapped-route",
        action="append",
        default=[],
        help="explicit test/static route glob allowed to omit the chain",
    )
    arguments = parser.parse_args()

    try:
        errors = audit(arguments.manifest, arguments.allow_unwrapped_route)
    except (OSError, tomllib.TOMLDecodeError) as error:
        print(f"error: cannot audit {arguments.manifest}: {error}", file=sys.stderr)
        return 1

    if errors:
        for error in errors:
            print(f"error: {error}", file=sys.stderr)
        return 1
    print(f"audited middleware coverage in {arguments.manifest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
