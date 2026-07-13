# Architecture

`wasi-auth` is the single authentication, authorization, and trusted-ingress
product. The production request path is:

```text
Browser / REST / gRPC
        |
        v
native trusted ingress
        |
        +--> verified context + embedded Cedar for the default REST hot path
        |
        v
HMAC-bound VerifiedAuthContext
        |
        v
authentication + organization + application services
        |
        +--> PostgreSQL relational command kernel --> embedded Cedar
        |
        +--> auth_outbox --> native mail / optional direct SpiceDB worker
```

Guest-composed component middleware and remote AuthZEN PDPs remain private
compatibility profiles. They are not part of `fullstack-spin` and cannot be
substituted into the production path without independently passing the same
security and performance gates.

## Trust boundary

Only validated ingress and authentication code can construct a
`VerifiedAuthContext`. It contains bounded principal, tenant, assurance,
session, request, and trusted-resource metadata. Application code cannot turn
arbitrary headers or request fields into verified authority; tests use the
explicit `testkit` builder.

Browser sessions use secure host-only HttpOnly cookies plus origin and CSRF
checks. Explicit API-client flows may receive tokens. Browser presenters never
serialize access or refresh tokens, and administration never accepts a shared
`admin_token` request field.

The public native listener serves HTTP/1.1 and HTTP/2 directly through Hyper.
It forwards streaming bodies and trailers without buffering, so Tonic unary,
server-streaming, client-streaming, and bidirectional-streaming preserve
backpressure and terminal status. Spin listens only on loopback or an
equivalent private pod network. A five-second HMAC envelope is bound to the
audience, method, path, and request ID; the guest strips external copies and
production rejects credential-bearing requests without a valid envelope.

## Application assembly

The production identity product is assembled from typed PostgreSQL services,
validated runtime configuration, embedded Cedar, and provider-specific outbox
workers. `AuthApplicationBuilder` remains available for generic integrations,
but it is not the persistence boundary of the relational product. Hot-path
Cedar selection is static. Optional direct SpiceDB selection uses concrete
types rather than a boxed provider per request.

Published Cedar bundles are content-addressed PostgreSQL records. The native
terminal loads the single active bundle with strict schema validation and
reloads it only after a stable transactional invalidation epoch. Guest gRPC or
cookie paths load the same authoritative bundle and fail closed on load or
validation failure. When no bundle has been published, both paths use the same
build-validated embedded default.

The authorization boundary is `DecisionProvider`: bounded `check`,
`batch_check`, and capability-reported resource listing. Only an explicit valid
allow proceeds. Denials, malformed context, provider errors, pending
revocations, unsupported obligations, and indeterminate results fail closed.
The older bounded AuthZEN contract remains available behind compatibility
packages but is not the default application call path.

## Persistence and secrets

PostgreSQL is the sole supported authentication product store. Every mutation
is one typed SQL command, so PostgreSQL itself is the atomic boundary. The
command updates authoritative relational rows, hashed or encrypted credential
records, idempotency state, audit data, authorization revisions, and outbox
intents together. No application callback can partially commit those
categories, and no event replay is required to reconstruct identity state.

Password hashes, TOTP secrets, WebAuthn challenge state, recovery-code hashes,
OAuth verifier state, refresh material, and signing references live in
purpose-specific tables. Raw one-time tokens and private signing material are
never stored. One lock-protected migration catalog is authoritative; SQLite is
not a production or parity claim.

Mail and relationship delivery share `auth_outbox`, but only secret-bearing
mail payloads are encrypted. Relationship rows contain bounded typed metadata
that the membership trigger inserts atomically with the authorization revision.
The native `wasi-auth-outbox-worker` leases rows with `FOR UPDATE SKIP LOCKED`,
performs at-least-once provider operations, and persists delivery IDs or
SpiceDB ZedTokens. Grant and revoke ordering is serialized per tuple. Optional
SpiceDB checks deny only when the matching resource has an unsettled row and
use that resource's newest delivered consistency token; one tenant's backlog
cannot block unrelated tenants.

## Domain boundaries

Users are global. Organizations, memberships, invitations, role assignments,
and audit records are tenant-scoped. Built-in roles are `owner`, `admin`,
`member`, and `viewer`; custom roles cannot grant ownership or system-level
permissions. Every active organization retains an owner, and system authority
is separate from organization roles and requires MFA step-up for sensitive
operations.

DDD remains appropriate for the generated application's business aggregates,
such as the counter example. Authentication itself is relational, and the
dependency points only from DDD consumers to `wasi-auth`.

Measured release evidence and the exact comparison boundary are documented in
[Performance and soak evidence](PERFORMANCE.md).
