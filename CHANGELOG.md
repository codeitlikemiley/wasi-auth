# Changelog

## Unreleased

- Clarified that Wasmtime is the final-WASI correctness reference and Spin is
  the upstream-blocked production-performance target.
- Classified component PDP services as experimental/compatibility profiles;
  production terminals embed Cedar and call SpiceDB directly.

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
