# wasi-auth

`wasi-auth` is the single public authentication and authorization crate for
WASI applications in this workspace. Its default feature set is empty; select
only the credential, policy, runtime, storage, and delivery adapters required
by the application.

The production Spin profile uses native trusted ingress, embedded Cedar, and
PostgreSQL. SpiceDB and portable component middleware are opt-in profiles.
