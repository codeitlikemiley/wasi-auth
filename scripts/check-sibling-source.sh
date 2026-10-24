#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

expected="$(compat_value wasi_http_middleware_revision)"
repository="$(compat_value wasi_http_middleware_repository)"
python3 - "${REPO_ROOT}/Cargo.lock" "${expected}" "${repository}" <<'PY'
import pathlib
import sys

lock_path, expected, repository = sys.argv[1:]
text = pathlib.Path(lock_path).read_text()
packages = text.split("[[package]]")
found = []
for block in packages:
    if '\nname = "wasi-http-metadata"' not in block:
        continue
    for line in block.splitlines():
        if line.startswith("source = "):
            found.append(line)
if len(found) != 1:
    print(
        f"error: expected one wasi-http-metadata source, found {len(found)}",
        file=sys.stderr,
    )
    raise SystemExit(1)
source = found[0]
needle = f"git+{repository}?rev={expected}#{expected}"
if needle not in source:
    print("error: middleware lock source does not match compatibility.toml", file=sys.stderr)
    print(f"expected: {needle}", file=sys.stderr)
    print(f"found: {source}", file=sys.stderr)
    raise SystemExit(1)
print(f"verified canonical middleware revision {expected}")
PY
