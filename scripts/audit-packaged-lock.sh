#!/usr/bin/env bash

# Audit the lockfile `cargo package` actually ships, not the workspace lockfile.
#
# These are different files. The workspace lock resolves every member of both
# workspaces; the packaged lock resolves only wasi-auth's own closure and is the
# one a `cargo install --locked wasi-auth` builds the outbox worker against.
# Auditing the workspace lock alone leaves the shipped one ungated, which is how
# 0.1.0-rc.2 reached crates.io carrying RUSTSEC-2026-0221 and a yanked spin.

set -euo pipefail

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/common.sh"

cd "${REPO_ROOT}"
require_command cargo
require_command cargo-audit
require_command python3
require_clean_tree
VERSION="$(compat_value version)"

package_args=(--locked --no-verify --package wasi-auth)
if [[ "${ALLOW_DIRTY:-0}" == "1" ]]; then
    package_args+=(--allow-dirty)
fi

# --no-verify keeps this cheap: the build is already verified by
# scripts/check-packages.sh, and only the archived lockfile is needed here.
cargo package "${package_args[@]}"

archive="${REPO_ROOT}/target/package/wasi-auth-${VERSION}.crate"
require_file "${archive}"

extracted="$(mktemp -d)"
trap 'rm -rf "${extracted}"' EXIT
lockfile="${extracted}/Cargo.lock"

# Read the lockfile out of the archive with Python rather than `tar xzf`. Cargo
# leaves bytes after the gzip stream, so gzip reports "trailing garbage ignored"
# and exits 2 even though every member decodes; under `set -e` that aborts a
# perfectly good archive. Python's tarfile reads the same archive without
# complaint, and pulling out one member is all this gate needs.
python3 - "${archive}" "wasi-auth-${VERSION}/Cargo.lock" "${lockfile}" <<'PY'
import pathlib
import sys
import tarfile

archive, member, destination = sys.argv[1:4]
with tarfile.open(archive) as bundle:
    try:
        source = bundle.extractfile(member)
    except KeyError:
        source = None
    if source is None:
        print(f"error: the archive carries no {member}: {archive}", file=sys.stderr)
        print(
            "       a binary-bearing crate must ship one for --locked installs",
            file=sys.stderr,
        )
        raise SystemExit(1)
    pathlib.Path(destination).write_bytes(source.read())
PY

# Yanked crates are denied as well as advisories. A yank is the registry's own
# statement that a version must not be used, and it reaches an installer the
# same way an advisory does.
#
# Yank status is the one part of this that needs the network. When the registry
# is unreachable, `cargo audit` reports that it could not check, then exits 0
# anyway if no advisory matched — so the check silently becomes a no-op exactly
# when it is least able to do its job. Treat an unperformed check as a failure.
audit_log="${extracted}/audit.log"
unchecked="couldn't check if the package is yanked"
attempts="${AUDIT_ATTEMPTS:-5}"
audit_status=1

for attempt in $(seq 1 "${attempts}"); do
    set +e
    cargo audit --deny warnings --deny yanked --file "${lockfile}" >"${audit_log}" 2>&1
    audit_status=$?
    set -e
    if ! grep -q "${unchecked}" "${audit_log}"; then
        break
    fi
    if [[ "${attempt}" -lt "${attempts}" ]]; then
        echo "warning: registry unreachable for yank status;" \
            "retrying (${attempt}/${attempts})" >&2
        sleep $((attempt * 5))
    fi
done

cat "${audit_log}"

if grep -q "${unchecked}" "${audit_log}"; then
    echo "error: the registry stayed unreachable across ${attempts} attempts," \
        "so yank status was never checked" >&2
    echo "       a gate that cannot perform its check must not report success" >&2
    exit 1
fi

if [[ "${audit_status}" -ne 0 ]]; then
    exit "${audit_status}"
fi

cat <<EOF
The wasi-auth ${VERSION} archive ships a lockfile with no advisories and no
yanked crates. This is the lockfile a --locked install of the outbox worker
resolves against, so it is gated separately from the workspace lockfile.
No package was uploaded.
EOF
