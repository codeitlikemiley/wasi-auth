# Security policy

This alpha is an authorization toolkit, not a credential verifier.
Authentication must establish the versioned upstream identity context. Never
place bearer tokens, cookies, passwords, client secrets, raw queries, request
bodies, or session secrets in authorization attributes.

Only an explicit valid allow decision may proceed. A false decision maps to 401
for an anonymous subject and 403 for an authenticated subject. Transport,
deadline, malformed-response, provider-indeterminate, PEP-authentication, and
unsupported-obligation failures map to a generic 503. PDP HTTP 401 or 403 means
the PEP itself failed to authenticate; it is never an application denial.

Authenticated identities are keyed by issuer and subject together. Domain
actions are stable identifiers rather than HTTP methods. Resource authorization
must run after loading the authoritative resource and immediately before a
mutation. UI hiding and coarse HTTP admission never replace this check.

## Trust boundaries

- The external HTTP PEP may send method and a normalized query-free path, but
  never body-derived ownership information.
- Attribute names and values are bounded and carry provenance. Callers remain
  responsible for sourcing each value from the declared trusted authority.
- Authentication metadata and provider credentials must not be logged. The
  contract cannot represent credentials, but custom transports must apply the
  same rule.
- Remote PDPs require TLS and production authentication such as host-managed
  mTLS. Loopback HTTP is development-only; `.spin.internal` is runtime-local.
- WASIp2 callers must inject their async runtime's cancellation-safe pollable
  waiter. A blocking `Pollable::block` adapter is unsupported because it can
  stall unrelated request work and cannot promptly release canceled I/O.
- The WASIp3 transport must drive request upload, send completion, bounded body
  collection, and provider-trailer disposal under the same absolute deadline.
  Dropping an unresolved host future is not accepted as successful cleanup.
  Duplicate, malformed, oversized, or body-mismatched `Content-Length` values
  fail closed, and transport errors never expose host-provided strings.
- Decision caching is unsupported. SpiceDB consistency tokens must travel with
  the protected resource revision when read-after-write semantics matter. The
  application must implement the [transaction/outbox sequence](docs/CONSISTENCY.md);
  no crate in this workspace makes the domain store and SpiceDB atomic.

## Dependency advisories

`paste` (`RUSTSEC-2024-0436`) and `proc-macro-error2`
(`RUSTSEC-2026-0173`) are temporarily allowed because Leptos 0.8 still pulls
them transitively. Both advisories describe unmaintained macro crates, not known
vulnerabilities. They are isolated from request data at runtime and must be
reviewed before every release; any newly reported vulnerability remains
blocking.

Report suspected security issues privately to the repository maintainers rather
than opening a public issue. Do not include credentials, identity envelopes, or
production policy data in a report.
