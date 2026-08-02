#!/usr/bin/env bash
#
# SessionStart hook for Claude Code on the web.
#
# Installs every tool this repository's gates need, at the exact versions
# `compatibility.toml` pins. Versions are never hardcoded here: they are read
# through `compat_value`, the same accessor the release scripts use, so a
# version bump in `compatibility.toml` flows here automatically.
#
# Downloaded tools land in `$HOME/.cache/leptos-wasi-tools/<name>-<version>/`,
# which `resolve_pinned_tool` in `scripts/common.sh` already searches. That
# means no environment variable is required for the scripts to find them, and
# the cache lives outside the repository so it survives both a fresh clone and
# `cargo clean`.
#
# Everything is idempotent: a tool already present at the pinned version is
# skipped, so re-running is cheap.
#
# The hook runs asynchronously, so the session starts immediately and
# provisioning continues in the background. A warm container finishes in under
# a second and a cold one in about eight, but that is still a race: work can
# begin before a tool exists. `$HOME/.cache/leptos-wasi-tools/.ready` is written
# last and names anything that failed, so a caller that needs certainty can
# wait for it:
#
#   until [ -f "$HOME/.cache/leptos-wasi-tools/.ready" ]; do sleep 1; done
#
# The marker is removed at the start of every run, so its presence always means
# "this run finished", never "a previous run once finished".
#
# Optional stages, off by default because they are large and rarely needed:
#   WASI_AUTH_SETUP_FUZZ=1       nightly toolchain + cargo-fuzz
#   WASI_AUTH_SETUP_PROVIDERS=1  SpiceDB + zed live-provider binaries
# Escape hatches:
#   WASI_AUTH_SETUP_SKIP_CARGO_TOOLS=1
#   WASI_AUTH_SETUP_SKIP_FETCH=1

set -euo pipefail

# Only provision the managed remote container. A local checkout keeps whatever
# the developer already has installed.
if [[ "${CLAUDE_CODE_REMOTE:-}" != "true" ]]; then
    exit 0
fi

# Hand the session back now and provision in the background. The timeout covers
# the worst realistic cold start: a container with no cargo-cyclonedx, which is
# the one tool still built from source.
echo '{"async": true, "asyncTimeout": 600000}'

# Everything from here is progress reporting, not hook protocol. Send it to
# stderr so nothing can be mistaken for a second control message on stdout.
exec 1>&2

HOOK_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# `common.sh` sets REPO_ROOT from its own location and provides compat_value,
# version_matches, sha256_file, and the require_* helpers.
# shellcheck source=/dev/null
source "${HOOK_DIR}/../../scripts/common.sh"

# rustup resolves rust-toolchain.toml from the working directory, and cargo
# subcommand installs should run against this workspace's toolchain, so do not
# depend on wherever the hook happened to be invoked from.
cd "${REPO_ROOT}"

TOOL_ROOT="${WASI_AUTHZ_TOOL_ROOT:-${HOME}/.cache/leptos-wasi-tools}"
READY_MARKER="${TOOL_ROOT}/.ready"
ARCH="$(uname -m)"

# Clear it up front so a marker left by an earlier run can never be read as
# this run having finished.
rm -f "${READY_MARKER}"

log() { printf '[wasi-auth setup] %s\n' "$*"; }

# A synchronous SessionStart hook gates the session, so one flaky download must
# not stop the user from working. Record what failed, keep going, and say so at
# the end; re-running the hook retries only the missing pieces.
MISSING=()
note_missing() {
    MISSING+=("$1")
    log "WARNING: could not install $1; continuing without it"
}

if [[ "${ARCH}" != "x86_64" ]]; then
    log "warning: prebuilt tool archives are selected for x86_64; found ${ARCH}."
    log "warning: downloads below may fail. Install tools manually if so."
fi

# --- stage 1: Rust toolchain -------------------------------------------------
#
# `rust-toolchain.toml` already pins the channel, the clippy/rustfmt
# components, and the wasm32-wasip2 target, so rustup materializes them on the
# first cargo invocation. Doing it here moves that cost out of the session.

MSRV="$(compat_value msrv)"
COMPONENT_TARGET="$(compat_value component_target)"

log "warming Rust ${MSRV} (from rust-toolchain.toml)"
rustup show active-toolchain >/dev/null

# CI runs a `stable` leg with the component target too. Without this, a build
# outside this repository — a sibling checkout with no rust-toolchain.toml —
# falls back to `stable` and fails with "can't find crate for `core`".
if rustup toolchain list | grep -q '^stable'; then
    if ! rustup target list --installed --toolchain stable \
        | grep -Fxq "${COMPONENT_TARGET}"; then
        log "adding ${COMPONENT_TARGET} to the stable toolchain"
        rustup target add "${COMPONENT_TARGET}" --toolchain stable
    fi
fi

# --- stage 2: pinned binary tools -------------------------------------------

# Extract one named binary out of an archive, whatever directory layout the
# upstream project happens to use, and install it where resolve_pinned_tool
# will find it.
download_binary_into() {
    local name="$1" version="$2" url="$3" archive_kind="$4" destination="$5"

    local scratch
    scratch="$(mktemp -d "${TMPDIR:-/tmp}/wasi-auth-tool.XXXXXX")"
    # shellcheck disable=SC2064
    trap "rm -rf '${scratch}'" RETURN

    case "${archive_kind}" in
        raw)
            curl --fail --location --retry 3 --silent --show-error \
                "${url}" --output "${scratch}/${name}"
            ;;
        tar.gz)
            curl --fail --location --retry 3 --silent --show-error \
                "${url}" --output "${scratch}/archive.tar.gz"
            tar -xzf "${scratch}/archive.tar.gz" -C "${scratch}"
            ;;
        tar.xz)
            curl --fail --location --retry 3 --silent --show-error \
                "${url}" --output "${scratch}/archive.tar.xz"
            tar -xJf "${scratch}/archive.tar.xz" -C "${scratch}"
            ;;
        *)
            echo "error: unknown archive kind: ${archive_kind}" >&2
            return 1
            ;;
    esac

    local extracted
    extracted="$(find "${scratch}" -type f -name "${name}" -perm -u+x -print -quit)"
    if [[ -z "${extracted}" ]]; then
        extracted="$(find "${scratch}" -type f -name "${name}" -print -quit)"
    fi
    if [[ -z "${extracted}" ]]; then
        echo "error: ${name} not found inside ${url}" >&2
        return 1
    fi

    mkdir -p "$(dirname "${destination}")"
    install -m 0755 "${extracted}" "${destination}"
}

# Install into the cache resolve_pinned_tool searches, keyed by version.
install_pinned_binary() {
    local name="$1" version="$2" url="$3" archive_kind="$4"
    local destination="${TOOL_ROOT}/${name}-${version}/${name}"

    if [[ -x "${destination}" ]] && version_matches "${destination}" "${version}"; then
        log "${name} ${version} already present"
        return 0
    fi

    log "installing ${name} ${version}"
    download_binary_into "${name}" "${version}" "${url}" "${archive_kind}" \
        "${destination}"
    require_version "${destination}" "${version}"
}

WASM_TOOLS_VERSION="$(compat_value wasm_tools)"
install_pinned_binary wasm-tools "${WASM_TOOLS_VERSION}" \
    "https://github.com/bytecodealliance/wasm-tools/releases/download/v${WASM_TOOLS_VERSION}/wasm-tools-${WASM_TOOLS_VERSION}-x86_64-linux.tar.gz" \
    tar.gz \
    || note_missing wasm-tools

WASMTIME_VERSION="$(compat_value wasmtime)"
install_pinned_binary wasmtime "${WASMTIME_VERSION}" \
    "https://github.com/bytecodealliance/wasmtime/releases/download/v${WASMTIME_VERSION}/wasmtime-v${WASMTIME_VERSION}-x86_64-linux.tar.xz" \
    tar.xz \
    || note_missing wasmtime

COSIGN_VERSION="$(compat_value cosign)"
install_pinned_binary cosign "${COSIGN_VERSION}" \
    "https://github.com/sigstore/cosign/releases/download/v${COSIGN_VERSION}/cosign-linux-amd64" \
    raw \
    || note_missing cosign

ORAS_VERSION="$(compat_value oras)"
install_pinned_binary oras "${ORAS_VERSION}" \
    "https://github.com/oras-project/oras/releases/download/v${ORAS_VERSION}/oras_${ORAS_VERSION}_linux_amd64.tar.gz" \
    tar.gz \
    || note_missing oras

# --- stage 3: cargo subcommands ---------------------------------------------
#
# These must be on PATH; there is no resolve_pinned_tool indirection for them.
#
# They come from upstream release assets directly rather than through a
# discovery-based installer. In this container the GitHub REST and GraphQL APIs
# both answer 403 — with or without a token — while
# `github.com/<org>/<repo>/releases/download/...` answers 200. Discovery
# therefore concludes no prebuilt binary exists and falls back to a source
# build, turning a seconds-long download into a multi-minute compile per tool.
# A direct URL sidesteps that. cargo-binstall and `cargo install` remain as
# fallbacks for anything whose asset is missing or renamed upstream.

# Some cargo subcommands refuse a bare `--version` and only answer through
# `cargo <subcommand> --version` (cargo-cyclonedx is one). Try both before
# concluding a tool is absent, otherwise every session reinstalls it.
cargo_tool_version() {
    local binary="$1" output
    if output="$("${binary}" --version 2>/dev/null)"; then
        printf '%s' "${output}"
        return 0
    fi
    if output="$(cargo "${binary#cargo-}" --version 2>/dev/null)"; then
        printf '%s' "${output}"
        return 0
    fi
    return 1
}

ensure_cargo_tool() {
    local crate="$1" binary="$2" version="$3" installed=""
    if command -v "${binary}" >/dev/null 2>&1 \
        && installed="$(cargo_tool_version "${binary}")" \
        && [[ "${installed}" == *"${version}"* ]]; then
        log "${binary} ${version} already present"
        return 0
    fi
    log "installing ${crate} ${version}"
    if command -v cargo-binstall >/dev/null 2>&1; then
        if cargo binstall --no-confirm --locked "${crate}@${version}"; then
            return 0
        fi
        log "binstall failed for ${crate}; building from source"
    fi
    cargo install --locked --version "${version}" "${crate}"
}

if [[ "${WASI_AUTH_SETUP_SKIP_CARGO_TOOLS:-0}" != "1" ]]; then
    if ! command -v cargo-binstall >/dev/null 2>&1; then
        log "installing cargo-binstall"
        scratch="$(mktemp -d "${TMPDIR:-/tmp}/wasi-auth-binstall.XXXXXX")"
        if curl --fail --location --retry 3 --silent --show-error \
            "https://github.com/cargo-bins/cargo-binstall/releases/latest/download/cargo-binstall-x86_64-unknown-linux-musl.tgz" \
            --output "${scratch}/cargo-binstall.tgz" \
            && tar -xzf "${scratch}/cargo-binstall.tgz" -C "${scratch}"; then
            mkdir -p "${CARGO_HOME:-${HOME}/.cargo}/bin"
            install -m 0755 "${scratch}/cargo-binstall" \
                "${CARGO_HOME:-${HOME}/.cargo}/bin/cargo-binstall"
        else
            log "cargo-binstall unavailable; falling back to source builds"
        fi
        rm -rf "${scratch}"
    fi

    # Tag conventions genuinely differ between these projects — cargo-deny
    # omits the leading `v`, cargo-audit nests the crate name in the tag — so
    # each URL is spelled out rather than derived from a single template.
    cargo_audit_version="$(compat_value cargo_audit)"
    cargo_deny_version="$(compat_value cargo_deny)"
    cargo_semver_checks_version="$(compat_value cargo_semver_checks)"
    cargo_hack_version="$(compat_value cargo_hack)"

    cargo_tool_releases=(
        "cargo-audit|${cargo_audit_version}|https://github.com/rustsec/rustsec/releases/download/cargo-audit%2Fv${cargo_audit_version}/cargo-audit-x86_64-unknown-linux-musl-v${cargo_audit_version}.tgz"
        "cargo-deny|${cargo_deny_version}|https://github.com/EmbarkStudios/cargo-deny/releases/download/${cargo_deny_version}/cargo-deny-${cargo_deny_version}-x86_64-unknown-linux-musl.tar.gz"
        "cargo-semver-checks|${cargo_semver_checks_version}|https://github.com/obi1kenobi/cargo-semver-checks/releases/download/v${cargo_semver_checks_version}/cargo-semver-checks-x86_64-unknown-linux-gnu.tar.gz"
        "cargo-hack|${cargo_hack_version}|https://github.com/taiki-e/cargo-hack/releases/download/v${cargo_hack_version}/cargo-hack-x86_64-unknown-linux-gnu.tar.gz"
    )

    for entry in "${cargo_tool_releases[@]}"; do
        IFS='|' read -r tool_binary tool_version tool_url <<<"${entry}"
        installed=""
        if command -v "${tool_binary}" >/dev/null 2>&1 \
            && installed="$(cargo_tool_version "${tool_binary}")" \
            && [[ "${installed}" == *"${tool_version}"* ]]; then
            log "${tool_binary} ${tool_version} already present"
            continue
        fi
        log "installing ${tool_binary} ${tool_version} from its release asset"
        if download_binary_into "${tool_binary}" "${tool_version}" \
            "${tool_url}" tar.gz \
            "${CARGO_HOME:-${HOME}/.cargo}/bin/${tool_binary}"; then
            # Not require_version: cargo-hack rejects a bare `--version` and
            # only answers through `cargo hack --version`.
            installed="$(cargo_tool_version "${tool_binary}")" || {
                echo "error: could not query ${tool_binary} version" >&2
                exit 1
            }
            if [[ "${installed}" != *"${tool_version}"* ]]; then
                log "${tool_binary} reports '${installed}', expected ${tool_version}"
                note_missing "${tool_binary}"
            fi
        else
            log "no usable release asset for ${tool_binary}; building it"
            ensure_cargo_tool "${tool_binary}" "${tool_binary}" "${tool_version}" \
                || note_missing "${tool_binary}"
        fi
    done

    # cargo-cyclonedx publishes no upstream binary. A third-party rebuild does
    # exist, but this is the tool that generates this repository's SBOMs, and
    # taking the SBOM generator itself from an unattested rebuilder is the one
    # place that trade is not worth making. Build it from the crates.io source
    # instead. It is the only compile left in the default path, and it happens
    # once per container image.
    ensure_cargo_tool cargo-cyclonedx cargo-cyclonedx "$(compat_value cargo_cyclonedx)" \
        || note_missing cargo-cyclonedx
fi

# --- stage 4: optional heavy extras -----------------------------------------

if [[ "${WASI_AUTH_SETUP_FUZZ:-0}" == "1" ]]; then
    FUZZ_TOOLCHAIN="$(compat_value fuzz_rust)"
    log "installing ${FUZZ_TOOLCHAIN} for cargo-fuzz"
    rustup toolchain install "${FUZZ_TOOLCHAIN}" --profile minimal
    ensure_cargo_tool cargo-fuzz cargo-fuzz "$(compat_value cargo_fuzz)"
fi

if [[ "${WASI_AUTH_SETUP_PROVIDERS:-0}" == "1" ]]; then
    log "installing checksum-verified SpiceDB and zed"
    PROVIDER_DIR="${TOOL_ROOT}/provider-tools"
    PROVIDER_TOOL_DIR="${PROVIDER_DIR}" \
        bash "${REPO_ROOT}/scripts/install-provider-tools.sh"
    PROVIDER_ENV_LINES=(
        "$(printf 'export SPICEDB_BIN=%q' "${PROVIDER_DIR}/spicedb")"
        "$(printf 'export ZED_BIN=%q' "${PROVIDER_DIR}/zed")"
    )
fi

# --- stage 5: prefetch dependencies -----------------------------------------
#
# The root workspace and the excluded legacy middleware workspace, so the first
# cargo command of the session compiles instead of downloading.
#
# `--locked` is deliberate and load-bearing: several release scripts call
# require_clean_tree, so a hook that regenerated a lockfile would leave the
# working tree dirty and block a release check. `fuzz/` is skipped for exactly
# that reason — its lockfile is behind its manifest, so fetching it would
# rewrite a tracked file. `cargo fuzz` fetches what it needs at run time.

if [[ "${WASI_AUTH_SETUP_SKIP_FETCH:-0}" != "1" ]]; then
    log "prefetching crates for the root and legacy workspaces"
    cargo fetch --locked --manifest-path "${REPO_ROOT}/Cargo.toml"
    cargo fetch --locked \
        --manifest-path "${REPO_ROOT}/legacy/wasi-http-middleware/Cargo.toml"
fi

# --- stage 6: report ---------------------------------------------------------

# Append only what is not already recorded: SessionStart fires on resume and
# compact as well as startup, and an env file that grows a duplicate line every
# time is noise.
record_env() {
    local line="$1"
    [[ -n "${CLAUDE_ENV_FILE:-}" ]] || return 0
    if [[ -f "${CLAUDE_ENV_FILE}" ]] && grep -qxF "${line}" "${CLAUDE_ENV_FILE}"; then
        return 0
    fi
    printf '%s\n' "${line}" >>"${CLAUDE_ENV_FILE}"
}

record_env "$(printf 'export WASI_AUTHZ_TOOL_ROOT=%q' "${TOOL_ROOT}")"
for line in "${PROVIDER_ENV_LINES[@]:-}"; do
    [[ -n "${line}" ]] && record_env "${line}"
done

# Written last, so its existence means this run reached the end. Anything that
# failed is named inside rather than signalled by the marker's absence, which
# would be indistinguishable from "still running".
mkdir -p "${TOOL_ROOT}"
if ((${#MISSING[@]} > 0)); then
    printf 'incomplete: %s\n' "${MISSING[*]}" >"${READY_MARKER}"
    log "NOT installed: ${MISSING[*]}"
    log "re-run .claude/hooks/session-start.sh to retry just those"
else
    printf 'complete\n' >"${READY_MARKER}"
fi

log "ready. Pinned tools resolve from ${TOOL_ROOT}"
log "  cargo test --workspace --locked --all-features"
log "  cargo clippy --workspace --locked --all-targets --all-features -- -D warnings"
log "  bash scripts/build-components.sh && bash scripts/check-component-contracts.sh"
if [[ "${WASI_AUTH_SETUP_PROVIDERS:-0}" != "1" ]]; then
    log "  SpiceDB/zed not installed; re-run with WASI_AUTH_SETUP_PROVIDERS=1 for live provider gates"
fi
if [[ "${WASI_AUTH_SETUP_FUZZ:-0}" != "1" ]]; then
    log "  cargo-fuzz not installed; re-run with WASI_AUTH_SETUP_FUZZ=1 for the fuzz gate"
fi
log "  PostgreSQL gates need a live server via WASI_AUTH_POSTGRES_TEST_URL"
