# Changelog

## Unreleased (post-0.1.0-rc.2)

- Added `scripts/audit-packaged-lock.sh` and a CI gate that audits the lockfile
  inside the published archive, denying both advisories and yanked crates. The
  workspace lockfile and the packaged lockfile are different files, and only
  the packaged one is what `cargo install --locked wasi-auth` resolves the
  outbox worker against. The published `0.1.0-rc.2` archive ships a lockfile
  carrying RUSTSEC-2026-0221 (`event-listener 5.4.1`) and a yanked
  `spin 0.9.8`; the repository's own lockfile is clean, and the gate now fails
  on an archive like that instead of letting it reach the registry.
- Corrected `companion.toml` and `docs/COMPATIBILITY.md`, which described the
  release-bundle evidence paths as files a consumer pins. They are git-ignored
  by design and resolve in no checkout at any revision; a consumer pins a
  revision for source and takes the evidence from the bundle a release run
  uploads. Crate and component paths are repository-relative and do resolve.

## 0.1.0-rc.2

- Added the first-class Resend mail adapter to the native outbox worker.
- Documented the outbox worker as a durable delivery process rather than an
  email server, including local and production process topology.

## Unreleased

- Consolidated authentication, authorization, trusted HTTP ingress, Leptos,
  Spin gRPC, Cedar, optional SpiceDB, mail, DDD/CQRS, and test helpers behind
  the single publishable `wasi-auth` crate. Legacy workspace crates are now
  non-publishable compatibility fixtures.
- Added bounded `VerifiedAuthContext` and authorization contracts, typestate
  application construction, static Cedar/SpiceDB provider dispatch, and
  fail-closed HTTP, Leptos, and gRPC guards.
- Added the single PostgreSQL relational auth schema, atomic unit-of-work
  support, idempotency records, secret references, durable mail and
  relationship outboxes, and the offline legacy migration tool. Removed the
  divergent migration-only Spin SQLite feature before the first RC.
- Added password, OAuth, passkey, MFA, rotating-session, organization,
  membership, invitation, role, policy-bundle, and audit workflows plus
  provider-neutral capture, SMTP, and HTTP mail adapters.
- Disabled every private RSA/PSS signing path process-wide because the
  RustCrypto RSA implementation has no patched release for its timing
  advisory. Production first-party tokens use ES256; RSA remains available
  only for public-key verification of identity-provider tokens.
- Reimplemented the supported terminal as native Hyper ingress with
  transactionally invalidated PostgreSQL context, active Cedar bundle reload,
  and streaming HTTP/2 proxying. Five protected-path pairs, five absolute
  samples, all four gRPC modes, and the ten-minute soak now pass on the
  maintained Spin fork with zero status or transport failures.
- Clarified that Wasmtime is the final-WASI correctness reference, upstream
  tagged Spin remains blocked, and the maintained Spin fork is the RC
  production-performance target.
- Classified component PDP services as experimental/compatibility profiles;
  production terminals embed Cedar and call SpiceDB directly.
- Added `companion.toml`, the generated record of the surface downstream
  consumers pin: all six path-dependency crates across both workspaces with
  their resolved versions and publishability, the three built components with
  their source directories, SBOMs, and WIT reports, and the release-bundle
  evidence paths. `scripts/generate-companion-manifest.sh` derives it from
  `cargo metadata` and CI rejects drift.
- Corrected the `wit-bindgen` version recorded in `compatibility.toml` from
  `0.59.0` to the `0.57.1` this workspace's component code actually binds
  with, and recorded the legacy middleware workspace's `0.59.0` separately.
  The HTTP PEP links both generators because it depends on
  `wasi-http-middleware-component-support`, so both values are load-bearing.
  The key had no script consumer, so the single stale value was never caught.

## 0.1.0-alpha.2

- Changed the Leptos bridge to require typed `VerifiedAuthContext` request
  extensions instead of implicitly trusting authentication wire headers.
- Added Cedar-first hybrid authorization metadata and enforcement that skips
  the relationship provider whenever Cedar denies.
- Aligned cross-repository CI checkout revisions with the single compatibility
  lock source of truth.

## 0.1.0-alpha.1

- Initial bounded AuthZEN 1.0 authorization contract.
- Transport, HTTP PEP, Cedar RBAC/ABAC, SpiceDB ReBAC, testkit, and typed
  Leptos integration crates.
- Native Cedar and final-WASIp3 Cedar and SpiceDB AuthZEN PDP services.
- Added final-WASI compatibility, provider, fuzz, package, and supply-chain gates.
- Documented forward-compatible AuthZEN extensions and strict `wasi_authz` parsing.
- Added an exact runtime/provider support matrix and explicit Spin canary status.
- Corrected the alpha WASIp2 client API to require an injected,
  cancellation-safe pollable waiter and enforce one absolute request deadline.
- Reworked the WASIp3 client to drive request upload, transmission, response,
  and trailer disposal under one absolute deadline without cross-executor
  spawning, with bounded response collection and strict `Content-Length` checks.
