#!/usr/bin/env python3
"""Measure a final-WASIp3 Cedar PDP candidate on an exact Wasmtime binary."""

from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import http.client
import json
import os
import platform
import socket
import subprocess
import tempfile
import threading
import time
from pathlib import Path


PDP_PATH = "/access/v1/evaluation"
PDP_TOKEN = "cedar-benchmark-bearer-token"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--wasmtime", required=True)
    parser.add_argument("--expected-version", required=True)
    parser.add_argument("--component", type=Path, required=True)
    parser.add_argument("--request", type=Path, required=True)
    parser.add_argument("--cold-starts", type=int, default=5)
    parser.add_argument("--requests", type=int, default=200)
    parser.add_argument("--concurrency", type=int, default=16)
    arguments = parser.parse_args()
    if arguments.cold_starts < 1:
        parser.error("--cold-starts must be positive")
    if arguments.requests < 1:
        parser.error("--requests must be positive")
    if arguments.concurrency < 1:
        parser.error("--concurrency must be positive")
    return arguments


def free_port() -> int:
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        return int(listener.getsockname()[1])


def percentile(values: list[float], fraction: float) -> float:
    ordered = sorted(values)
    index = round((len(ordered) - 1) * fraction)
    return ordered[index]


def request_once(port: int, body: bytes) -> tuple[int, float, bytes]:
    started = time.perf_counter()
    connection = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    try:
        connection.request(
            "POST",
            PDP_PATH,
            body=body,
            headers={
                "authorization": f"Bearer {PDP_TOKEN}",
                "content-type": "application/json",
            },
        )
        response = connection.getresponse()
        response_body = response.read()
        return response.status, (time.perf_counter() - started) * 1_000, response_body
    finally:
        connection.close()


def validate_response(status: int, response_body: bytes) -> None:
    if status != 200:
        raise RuntimeError(f"PDP returned HTTP {status}")
    document = json.loads(response_body)
    if document.get("decision") is not True:
        raise RuntimeError("PDP fixture decision was not true")


class WasmtimeServer:
    def __init__(
        self,
        wasmtime: str,
        component: Path,
        log_path: Path,
    ) -> None:
        self.port = free_port()
        self._log = log_path.open("wb")
        self.process = subprocess.Popen(
            [
                wasmtime,
                "serve",
                "-W",
                "component-model-async=y",
                "-S",
                "p3=y",
                "-S",
                "cli=y",
                "-S",
                "http=y",
                "--addr",
                f"127.0.0.1:{self.port}",
                "--env",
                f"WASI_AUTHZ_PDP_BEARER_TOKEN={PDP_TOKEN}",
                str(component),
            ],
            stdout=self._log,
            stderr=subprocess.STDOUT,
        )

    def wait_until_ready(self, body: bytes, timeout_seconds: float = 15) -> float:
        started = time.perf_counter()
        deadline = started + timeout_seconds
        while time.perf_counter() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError(f"Wasmtime exited with {self.process.returncode}")
            try:
                status, _, response_body = request_once(self.port, body)
                validate_response(status, response_body)
                return (time.perf_counter() - started) * 1_000
            except (ConnectionError, OSError):
                time.sleep(0.005)
        raise RuntimeError("Wasmtime did not become ready before the deadline")

    def close(self) -> None:
        if self.process.poll() is None:
            self.process.terminate()
            try:
                self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
        self._log.close()

    def __enter__(self) -> "WasmtimeServer":
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def resident_kib(process_id: int) -> int | None:
    result = subprocess.run(
        ["ps", "-o", "rss=", "-p", str(process_id)],
        check=False,
        capture_output=True,
        text=True,
    )
    try:
        return int(result.stdout.strip())
    except ValueError:
        return None


def assert_log_is_redacted(log_path: Path) -> None:
    log = log_path.read_text(errors="replace")
    for sentinel in (PDP_TOKEN, "cold-start-probe", "leptos-wasi-counter"):
        if sentinel in log:
            raise RuntimeError("Wasmtime/PDP log disclosed request or credential data")


def load_probe(
    server: WasmtimeServer,
    body: bytes,
    request_count: int,
    concurrency: int,
) -> dict[str, object]:
    for _ in range(min(10, request_count)):
        status, _, response_body = request_once(server.port, body)
        validate_response(status, response_body)

    peak_rss = [resident_kib(server.process.pid) or 0]
    stop_monitor = threading.Event()

    def monitor() -> None:
        while not stop_monitor.wait(0.01):
            sample = resident_kib(server.process.pid)
            if sample is not None:
                peak_rss[0] = max(peak_rss[0], sample)

    monitor_thread = threading.Thread(target=monitor, daemon=True)
    monitor_thread.start()
    started = time.perf_counter()
    errors: list[str] = []
    latencies: list[float] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(request_once, server.port, body) for _ in range(request_count)]
        for future in concurrent.futures.as_completed(futures):
            try:
                status, latency, response_body = future.result()
                validate_response(status, response_body)
                latencies.append(latency)
            except Exception as error:  # noqa: BLE001 - errors are reported, then fail the gate.
                errors.append(type(error).__name__)
    elapsed = time.perf_counter() - started
    stop_monitor.set()
    monitor_thread.join(timeout=1)
    if errors:
        raise RuntimeError(f"{len(errors)} load requests failed: {sorted(set(errors))}")
    return {
        "requests": request_count,
        "concurrency": concurrency,
        "errors": 0,
        "throughput_requests_per_second": round(request_count / elapsed, 2),
        "latency_ms": {
            "p50": round(percentile(latencies, 0.50), 3),
            "p95": round(percentile(latencies, 0.95), 3),
            "p99": round(percentile(latencies, 0.99), 3),
            "max": round(max(latencies), 3),
        },
        "peak_host_rss_kib": peak_rss[0],
    }


def main() -> None:
    arguments = parse_args()
    version = subprocess.run(
        [arguments.wasmtime, "--version"],
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    if arguments.expected_version not in version:
        raise RuntimeError(
            f"Wasmtime version mismatch: expected {arguments.expected_version}, found {version}"
        )
    body = arguments.request.read_bytes()
    component_bytes = arguments.component.read_bytes()
    with tempfile.TemporaryDirectory(prefix="wasi-authz-wasmtime-") as temporary:
        temporary_path = Path(temporary)
        cold_starts: list[float] = []
        for index in range(arguments.cold_starts):
            log_path = temporary_path / f"cold-{index}.log"
            with WasmtimeServer(arguments.wasmtime, arguments.component, log_path) as server:
                cold_starts.append(server.wait_until_ready(body))
            assert_log_is_redacted(log_path)

        load_log = temporary_path / "load.log"
        with WasmtimeServer(arguments.wasmtime, arguments.component, load_log) as server:
            server.wait_until_ready(body)
            load = load_probe(server, body, arguments.requests, arguments.concurrency)
        assert_log_is_redacted(load_log)

    report = {
        "artifact": {
            "bytes": len(component_bytes),
            "sha256": hashlib.sha256(component_bytes).hexdigest(),
        },
        "runtime": version,
        "platform": {
            "system": platform.system(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        },
        "flags": [
            "-W component-model-async=y",
            "-S p3=y",
            "-S cli=y",
            "-S http=y",
        ],
        "cold_start_ms": {
            "trials": [round(value, 3) for value in cold_starts],
            "p50": round(percentile(cold_starts, 0.50), 3),
            "p95": round(percentile(cold_starts, 0.95), 3),
            "max": round(max(cold_starts), 3),
        },
        "load": load,
    }
    print(json.dumps(report, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()
