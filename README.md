# wasi-authz

`wasi-authz` is a transport-neutral, fail-closed authorization toolkit for
WASI services. It implements a bounded profile of the OpenID AuthZEN
Authorization API 1.0 and keeps policy enforcement independent from Cedar,
SpiceDB, Spin, Wasmtime, and Leptos.

Current version: `0.1.0-alpha.1`.

The workspace is intentionally split into small crates:

- `wasi-authz-contract`: bounded AuthZEN request and decision types.
- `wasi-authz-client`: transport-neutral PEP client with additive WASI HTTP transports.
- `wasi-authz-testkit`: provider conformance fixtures.
- `wasi-authz-http`: coarse HTTP route enforcement helpers.
- `wasi-authz-cedar`: embedded Cedar RBAC/ABAC provider.
- `wasi-authz-spicedb`: Zanzibar-style SpiceDB adapter.
- `leptos-wasi-authz`: typed Leptos request context and server-function integration.

This alpha does not cache authorization decisions and does not accept decision
obligations. Anything other than an explicit, valid allow decision fails
closed.

```rust
use wasi_authz_contract::{
    AccessEvaluation, Action, AuthenticatedSubjectV1, EntityIdV1, EntityTypeV1,
    IssuerV1, Resource, SubjectV1,
};

let subject = AuthenticatedSubjectV1::new(
    EntityTypeV1::new("user")?,
    EntityIdV1::new("alice")?,
    IssuerV1::new("https://identity.example")?,
);
let evaluation = AccessEvaluation::new(
    SubjectV1::Authenticated(subject),
    Action::new("order.update")?,
    Resource::new("order", "order-123")?,
);

assert_eq!(evaluation.action().name().as_str(), "order.update");
# Ok::<(), wasi_authz_contract::ContractError>(())
```

See [Architecture](docs/ARCHITECTURE.md) and
[Compatibility](docs/COMPATIBILITY.md).
