#!/usr/bin/env bash

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cargo_fuzz_bin="${CARGO_FUZZ_BIN:-cargo-fuzz}"
require_version "${cargo_fuzz_bin}" "$(compat_value cargo_fuzz)"
fuzz_toolchain="${FUZZ_RUST_TOOLCHAIN:-$(compat_value fuzz_rust)}"
runs="${FUZZ_RUNS:-10000}"

for target in authzen-json attributes provider-response; do
    (
        cd "${REPO_ROOT}"
        RUSTUP_TOOLCHAIN="${fuzz_toolchain}" \
            "${cargo_fuzz_bin}" fuzz run "${target}" -- -runs="${runs}"
    )
done
