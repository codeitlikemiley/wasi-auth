# wasi-auth

`wasi-auth` is the single public authentication and authorization crate for
WASI applications in this workspace. Its default feature set is empty; select
only the credential, policy, runtime, storage, and delivery adapters required
by the application.

The production Spin profile uses native trusted ingress, embedded Cedar, and
PostgreSQL. SpiceDB and portable component middleware are opt-in profiles.
The ingress and guest exchange only short-lived, request-bound HMAC envelopes;
arbitrary public headers cannot construct a `VerifiedRequestContext`.

The authentication source of truth is the PostgreSQL relational command
kernel, not DDD events. Each typed mutation is one parameterized SQL statement
covering locks, credentials, idempotency, audit, authorization revisions, and
durable outbox insertion. Secret mail payloads are encrypted; relationship
intents are bounded typed metadata. `auth_outbox` is the only delivery queue.
