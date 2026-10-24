# Security policy

This alpha consolidates authentication and authorization. Only validated
authentication ingress may construct `VerifiedAuthContext`; application code
must never promote arbitrary headers. Never place bearer tokens, cookies,
passwords, client secrets, raw queries, request bodies, or session secrets in
authorization attributes.

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

- Only [`crates/wasi-auth/src/http.rs`](crates/wasi-auth/src/http.rs)'s HMAC
  envelope may become a `VerifiedAuthContext`. The portable
  `wasi-http-middleware` context uses the same `x-wasi-auth-context` header
  name and an unsigned base64url JSON encoding. Those bytes are not
  interchangeable: the signed opener rejects the portable encoding, and this
  crate does not parse the portable encoding as authority.
- Native ingress strips every `x-wasi-auth-*` header and the legacy
  `x-auth-session` / `x-auth-admin-token` headers before authentication, then
  installs one sensitive HMAC envelope. Authorization and session cookies are
  removed before the loopback guest sees the request. The guest acceptor
  fails closed when those credentials are still present, when a verified
  context is already installed, or when the envelope is missing, duplicated,
  tampered, rebound to another method, path, or request ID, expired, or sealed
  more than one second in the future.
- `accept_signed_trusted_context` accepts each exact envelope once in the
  guest process. A second presentation fails closed as replay, including an
  immediate retry of the same method, path, and request ID. The MAC still
  binds audience, method, path, and request ID, so those bytes cannot
  authorize a different request. The freshness window remains one to thirty
  seconds (default five). `TrustedContextCodec::open` checks that window and
  does not consume the envelope.
- The seen-set lives in the guest process. A second instance that shares the
  HMAC key can accept the same envelope until the freshness window ends.
  There is no cross-instance nonce store. Ingress strips every client
  `x-wasi-auth-*` header, including a correctly signed client envelope, so
  the public listener does not honor a captured envelope. The residual replay
  requires a caller who can reach the guest directly. Loopback is the
  deployment rule; it is not the security proof.
- Query strings and bodies are not part of the HMAC binding.
- CORS and browser security headers are single-owner. `CorsConfig::apply` and
  `apply_response_security` leave a response unchanged when another policy,
  including portable middleware's `strict-origin-when-cross-origin` referrer
  policy, is already present. A response with two values for one of those
  headers is conflicting and must be discarded.
- The coarse HTTP PEP and `wasi-http-authn::accept_trusted_ingress` belong to
  the unsigned portable chain. Do not place them on the native HMAC path.
  They will fail closed on a signed envelope, which is the safe outcome, but
  it is not a supported composition. Shared policy extraction was not done:
  the portable parser's guarantees and the HMAC binding are different
  contracts.
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

`rsa 0.9.10` is covered by `RUSTSEC-2023-0071`, which warns that private RSA
operations can leak key information through remotely observable timing. It is
retained only to verify provider-issued RS256 ID-token signatures, a public-key
operation with no application secret. The process-wide `wasi-auth` JWT crypto
provider rejects every RSA/PSS signing algorithm and RSA private-key JWK
extraction, and the production template accepts only ES256 private signing
keys. Tests enforce that denial. This narrow exception must be removed when a
constant-time upstream release is available or provider verification moves to
a dependency without the advisory; using this dependency for private RSA
operations remains prohibited.

Report suspected security issues privately to the repository maintainers rather
than opening a public issue. Do not include credentials, identity envelopes, or
production policy data in a report.
