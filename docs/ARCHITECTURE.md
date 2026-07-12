# Architecture

`wasi-auth` is the single authentication, authorization, and trusted-ingress
product. The production request path is:

```text
Browser / REST / gRPC
        |
        v
native trusted ingress
        |
        v
VerifiedAuthContext
        |
        v
authentication + organization + application services
        |
        +--> embedded Cedar --> DDD unit of work --> PostgreSQL
        |
        +--> direct SpiceDB when the optional ReBAC feature is enabled
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

## Application assembly

`AuthApplicationBuilder` uses typestate to require a store, authorizer, mailer,
secret store, clock, and randomness source before it can build an application.
Hot-path Cedar selection is static. Optional direct SpiceDB selection uses a
bounded enum rather than a boxed provider per request.

The authorization boundary is `DecisionProvider`: bounded `check`,
`batch_check`, and capability-reported resource listing. Only an explicit valid
allow proceeds. Denials, malformed context, provider errors, pending
revocations, unsupported obligations, and indeterminate results fail closed.
The older bounded AuthZEN contract remains available behind compatibility
packages but is not the default application call path.

## Persistence and secrets

`AuthUnitOfWork` atomically commits aggregate events, projections, secret
references, idempotency records, and mail or relationship outbox intents.
PostgreSQL is authoritative in production; Spin SQLite implements the same
versioned schema contract for development.

Immutable events never carry password hashes, TOTP secrets, WebAuthn challenge
state, recovery-code hashes, OAuth verifier state, or signing material. Those
values live in dedicated hashed or encrypted records. Events carry only
credential identifiers, versions, and non-secret lifecycle metadata.

Relationship revocations deny while their SpiceDB outbox intent is pending;
grants remain unavailable until confirmed. Matching protected-resource
revisions carry the returned consistency token. Mail delivery uses a durable
typed outbox with capture available only for development.

## Domain boundaries

Users are global. Organizations, memberships, invitations, role assignments,
and audit records are tenant-scoped. Built-in roles are `owner`, `admin`,
`member`, and `viewer`; custom roles cannot grant ownership or system-level
permissions. Every active organization retains an owner, and system authority
is separate from organization roles and requires MFA step-up for sensitive
operations.

The DDD dependency points one way: optional `wasi-auth` modules depend on
`ddd_cqrs_es`; the DDD core never depends on identity or authorization code.
