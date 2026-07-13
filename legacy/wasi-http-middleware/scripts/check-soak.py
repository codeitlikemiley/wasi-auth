#!/usr/bin/env python3
"""Validate HTTP soak results and detect sustained resident-memory growth."""

from __future__ import annotations

import json
import pathlib
import statistics
import sys


def main() -> int:
    result_path = pathlib.Path(sys.argv[1])
    memory_path = pathlib.Path(sys.argv[2])
    summary_path = pathlib.Path(sys.argv[3])

    result = json.loads(result_path.read_text())
    status_codes = result.get("statusCodeDistribution", {})
    if result["summary"]["successRate"] != 1.0:
        raise RuntimeError("soak contained unsuccessful requests")
    if result.get("errorDistribution"):
        raise RuntimeError(f"soak contained client errors: {result['errorDistribution']}")
    if set(status_codes) != {"200"}:
        raise RuntimeError(f"soak returned unexpected statuses: {status_codes}")

    samples = []
    for line in memory_path.read_text().splitlines():
        if not line.strip():
            continue
        elapsed, application, policy = (int(value) for value in line.split("\t"))
        samples.append((elapsed, application, policy))
    if len(samples) < 3:
        raise RuntimeError("soak did not record enough memory samples")

    second_half = samples[len(samples) // 2 :]
    window = max(1, len(second_half) // 5)
    start_rss = statistics.median(sample[1] for sample in second_half[:window])
    end_rss = statistics.median(sample[1] for sample in second_half[-window:])
    growth_kib = end_rss - start_rss
    allowed_growth_kib = max(32 * 1024, start_rss * 0.10)
    if growth_kib > allowed_growth_kib:
        raise RuntimeError(
            f"application RSS did not plateau: growth={growth_kib} KiB "
            f"allowed={allowed_growth_kib:.0f} KiB"
        )

    summary = {
        "requests": sum(int(count) for count in status_codes.values()),
        "requests_per_second": result["summary"]["requestsPerSec"],
        "p99_seconds": result["latencyPercentiles"]["p99"],
        "memory_samples": len(samples),
        "application_rss_start_kib": start_rss,
        "application_rss_end_kib": end_rss,
        "application_rss_growth_kib": growth_kib,
        "application_rss_peak_kib": max(sample[1] for sample in samples),
        "policy_rss_peak_kib": max(sample[2] for sample in samples),
    }
    summary_path.write_text(json.dumps(summary, indent=2, sort_keys=True) + "\n")
    print(summary_path.read_text(), end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
