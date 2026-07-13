# Configuration

Configuration is loaded once per component instance. Duplicate keys, missing
required values, or invalid bounds produce a controlled generic 503. Do not
reuse one instance across tenants with different policy.

## Request ID and security headers

`request-id` has no configuration. It accepts exactly one non-empty
`x-request-id`, at most 128 characters from `A-Z a-z 0-9 - _ . : /`; all other
forms are replaced with a 48-character lowercase hexadecimal ID. Each
component instance obtains one random 128-bit prefix, then appends a monotonic
64-bit sequence. The value is unique within that instance until the sequence
wraps and is a correlation identifier, never a credential.

`security-headers` has no configuration and sets:

| Header | Value |
|---|---|
| `X-Content-Type-Options` | `nosniff` |
| `Referrer-Policy` | `strict-origin-when-cross-origin` |

CSP is application-specific, especially for islands/split Wasm. HSTS belongs
at the TLS terminator.

## CORS

| Variable | Required | Default |
|---|---:|---|
| `WASI_MIDDLEWARE_CORS_ORIGINS` | yes | none |
| `WASI_MIDDLEWARE_CORS_METHODS` | no | `GET,HEAD,POST` |
| `WASI_MIDDLEWARE_CORS_HEADERS` | no | `content-type,authorization` |
| `WASI_MIDDLEWARE_CORS_ALLOW_CREDENTIALS` | no | `false` |

Origins are exact serialized `http`/`https` origins (or explicit `null`). `*`
cannot be combined with credentials. A valid preflight returns 204 before
authentication. Origin-dependent responses include `Vary: Origin` without
discarding existing Vary tokens.

## Authentication broker

| Variable | Required | Default | Constraint |
|---|---:|---|---|
| `WASI_MIDDLEWARE_AUTHN_BROKER_URL` | yes | none | HTTPS; Spin-internal HTTP exception; explicit loopback development exception |
| `WASI_MIDDLEWARE_AUTHN_TIMEOUT_MS` | no | `2000` | `1..=60000` |
| `WASI_MIDDLEWARE_AUTHN_MODE` | no | `required` | `required` or `optional` |
| `WASI_MIDDLEWARE_SERVICE_ID` | yes | none | bounded realm-safe token |
| `WASI_MIDDLEWARE_AUTHN_AUDIENCES` | yes | none | non-empty bounded comma-separated OAuth resource identifiers |
| `WASI_MIDDLEWARE_AUTHN_MAX_IN_FLIGHT` | no | `64` | `1..=1024` |
| `WASI_MIDDLEWARE_AUTHN_ALLOW_INSECURE_LOOPBACK` | no | `false` | exactly `true` or `false` |

Plain HTTP is rejected except for one-label `<service>.spin.internal` names or
an IP/`localhost` loopback URL when the explicit development flag is true.
User information, ambiguous suffixes, and remote HTTP are rejected.

Optional mode skips the broker only when `Authorization` is absent. A supplied
credential is always verified and is never downgraded to anonymous access.
Broker URL, service ID, and audiences remain required in both modes.
`service_id` names the terminal deployment; audiences are expected OAuth
resource identifiers and need not equal it (for example, `orders-api` and
`api://orders`).

The broker request is `POST application/json` with the credential only in its
`Authorization` header. Its strict JSON body is:

```json
{
  "version": 1,
  "service_id": "orders-api",
  "audiences": ["api://orders"],
  "request_id": "..."
}
```

Method, scheme, authority, route/path, query, cookies, and body are deliberately
absent. Authentication establishes identity; route/resource authorization
belongs later in the application.

A 200 response must use the strict V1 schema. Unknown fields, invalid bounds,
or inconsistent claims fail closed:

```json
{
  "version": 1,
  "issuer": "https://issuer.example",
  "subject": "user-1",
  "tenant_id": "tenant-1",
  "roles": ["member"],
  "scopes": ["read"],
  "acr": "urn:example:loa:2",
  "amr": ["pwd"],
  "actor": {"issuer": "workload.example", "subject": "job-1"},
  "auth_time": 1700000000,
  "expires_at": 1700003600,
  "session_id": "session-1",
  "decision_id": "decision-1",
  "policy_revision": "r7"
}
```

Only issuer, subject, decision ID, and policy revision are mandatory success
fields. Actor identity is also an `(issuer, subject)` pair. Roles, scopes, AMR,
and audiences are bounded, sorted, and de-duplicated before encoding.

Broker 401 maps to an invalid-credential RFC 6750 challenge. A broker 403 is
not accepted as domain authorization evidence and therefore maps, along with
network error, saturation, timeout, unexpected status, malformed JSON, or an
oversized response, to generic 503 with `Retry-After: 1`. RBAC, ABAC, and ReBAC
denials belong to the downstream authorization boundary. One monotonic deadline
races connect, response headers, each body frame, and cancellation; irrelevant
broker trailers are dropped.

## Trusted context

On pass, middleware removes `Authorization` and every inbound
`x-wasi-auth-*` field, then inserts exactly one `x-wasi-auth-context`. The value
is bounded canonical base64url-without-padding JSON, version 1. Anonymous
contexts contain no principal/decision. Authenticated contexts bind immutable
service/audiences to validated broker claims. Every response removes the
reserved prefix so the context never becomes browser-visible.

The encoded context and converted Authorization, cookie, and reserved trusted
metadata header values are marked sensitive in Rust header maps. Public
identity/context types use redacted `Debug` implementations. These safe
defaults reduce accidental diagnostic disclosure; they do not authorize code
to log header accessors or decoded identity fields.

## Fused component

`secure-defaults` consumes the same CORS and authentication environment. CORS
is initialized/evaluated first, so valid preflight never depends on broker
availability. Golden tests compare it with the four-component chain.

## Diagnostics

Set `WASI_MIDDLEWARE_DIAGNOSTICS=true` only in a local capacity investigation.
The components then emit fixed stage labels for fail-closed paths, for example
`authn_admission`, `authn_transport`, `authn_deadline`, or
`authn_protocol`. No request ID, credential, cookie, query, body, identity, or
provider response is logged. The setting is disabled by default and should not
be enabled on a normal production listener because it emits one record per
classified failure.
