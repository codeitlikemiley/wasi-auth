# Trust boundary

## Required invariant

The terminal trusts `x-wasi-auth-context` only when every externally reachable
route passes through the declared component boundary. No second trigger,
service address, or ingress route may reach it directly. Run
`audit-spin-manifest.py` for future native Spin manifests; current Spin final-WIT
fixtures are compatibility canaries, not deployable production manifests.
Pinned Spin main can run a plain final-WASI terminal, but composed middleware
on the ordinary build is still blocked and native trigger middleware still
uses release-candidate WIT.

The context is metadata, not a credential. Middleware first strips the client
`Authorization` value and every reserved header, then inserts one validated
context. The terminal must reject the header when composition is not guaranteed.

## Responsibilities

| Boundary | Responsibilities |
|---|---|
| Ingress/host | TLS/HSTS, WAF, trusted proxy data, global deadlines, distributed limits, static assets |
| Component boundary | Request ID, conservative response headers, CORS, credential verification, metadata sanitization |
| Authentication broker | Credential, issuer/key lifecycle, revocation, identity claims |
| Application | Resource ownership and domain authorization |

Request ID and security headers import no environment or outbound HTTP. CORS
imports environment only. Authentication imports environment, monotonic clocks,
random, and WASI HTTP client. Deployment must grant only the exact configured
broker origin. `authn-policy` sends no request authorization inputs beyond the
credential itself and immutable deployment/request IDs.

## Failure policy

- Invalid cached configuration returns generic 503, never a raw host error.
- Duplicate/oversized/malformed Authorization returns 400 without a broker call.
- Missing credentials return 401 in required mode or anonymous context in
  optional mode.
- Supplied invalid credentials return 401; optional mode never fails open.
- Broker 403 and every non-authentication status fail closed as generic 503;
  domain 403 decisions belong to a separate authorization provider.
- Broker failure, deadline, saturation, malformed success, or unknown status is
  503.
- Body-result errors propagate after already-delivered frames; middleware does
  not buffer or convert them into successful completion.

## Sensitive data

Never log credentials, cookies, bodies, raw queries, trusted identity values,
session IDs, or context headers. A request ID is loggable only after canonical
validation. Safe telemetry includes status, duration, byte counts, middleware
class, and coarse error class.

Canonical context values and sensitive inbound header values carry Rust's
`HeaderValue::is_sensitive` marker, and public authentication identity types
redact their `Debug` output. Treat these as defense in depth: application code
must still avoid logging decoded accessors and must configure host/proxy logs
to exclude request secrets.

The mock broker uses deterministic test tokens (`Bearer allow`, `readonly`,
`lowacr`, `no-relation`, `deny`, `error`, and failure variants). It must never
be deployed as an identity
provider. Local supply-chain signing keys are ephemeral and dry-run-only;
promotion requires CI keyless signing or an approved release identity.
