# Changelog

All notable changes are documented here.

## [Unreleased]

- Clarified that portable guest middleware remains an experimental
  interoperability path rather than a deprecated production fallback.
- Documented trusted native ingress as the production use of the shared policy,
  metadata, and in-process authentication crates.

## [0.2.0-alpha.2] - 2026-07-11

### Added

- A publishable, transport-neutral `wasi-http-authn` crate for trusted-ingress
  and statically dispatched terminal-broker authentication.
- Typed `VerifiedAuthContext` propagation through `http::Extensions` so trusted
  identity is removed from the wire before terminal application dispatch.

### Changed

- The guest `secure-defaults` stack is now a portable experimental fallback,
  not the recommended production architecture. It remains for this alpha and
  remains available as an experimental interoperability fixture.

## [0.2.0-alpha.1] - 2026-07-10

### Breaking

- Migrated every component from the March RC to final `wasi:http@0.3.0`.
- Replaced `auth-policy` and legacy identity headers with strict
  `authn-policy` and bounded `AuthContextV1` in `x-wasi-auth-context`.
- Renamed the deterministic policy fixture to `mock-authn-broker`.

### Added

- Required/optional authentication, immutable service/audience binding,
  HTTPS/Spin-internal/dev-loopback URL policy, RFC 6750 challenges, one total
  deadline, cancellation-safe bounded admission, and strict broker schemas.
- A fused `secure-defaults` component with golden parity against the separate
  request-ID/security/CORS/authn chain.
- ACR, AMR, issuer-scoped actor identity, roles, scopes, tenant/session claims,
  decision ID, and policy revision in the versioned context.
- Distinct immutable terminal service IDs and expected OAuth audiences, such as
  `orders-api` with `api://orders`.
- Wasmtime 46 behavioral suites, fuzz targets, final-WIT contract reports,
  deterministic SBOM/checksum evidence, local OCI layout, provenance, and
  ephemeral signature dry runs.

### Fixed

- Relayed forwarded request/response transmission results to prevent stacked
  middleware from canceling a producer and intermittently losing the first
  frame before a terminal stream error.
- Closed producers before publishing body results and joined outbound authn
  request transmission with body production, response collection, fail-fast
  cancellation, and the one absolute deadline.
- Removed credentials/spoofed metadata before downstream invocation and removed
  all trusted authentication metadata from client responses.
- Marked canonical authentication contexts, Authorization, cookies, and
  reserved trusted metadata as sensitive header values, and redacted public
  identity/authentication `Debug` implementations.

### Performance

- Reused a per-instance random request-ID prefix with a monotonic sequence,
  cached the deterministic anonymous authentication context, moved environment
  reads behind one-time initialization, and removed redundant header
  conversions while preserving immutable WASI resource lifecycles.

### Compatibility

- Wasmtime 46.0.1 is the only passing behavioral host in this alpha.
- Spin 4.0.0 lacks final-WASI resources and the pinned middleware revision is
  RC-only; both are explicit expected-incompatibility canaries.

## [0.1.0-alpha.1] - 2026-07-10

- Initial March-2026-RC request-ID, security-header, CORS, and external-policy
  middleware prototype.
