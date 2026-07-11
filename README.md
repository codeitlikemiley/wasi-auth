# wasi-authz

`wasi-authz` is a transport-neutral, fail-closed authorization toolkit for
WASI services. It implements a bounded profile of the OpenID AuthZEN
Authorization API 1.0 and keeps policy enforcement independent from Cedar,
SpiceDB, Spin, Wasmtime, and Leptos.

Current version: `0.1.0-alpha.3`.

The tested baseline is Rust 1.93, `wasip3` 0.7.0 with final
`wasi:http@0.3.0`, and Wasmtime 46.0.1. Tagged Spin 4.0.2 cannot link the
final-WASI components; Spin `main` at
`c34c584dbf77b3a3528ad0536aa9ce4761b9f772` (`4.1.0-pre0`) is an experimental
terminal and outbound-HTTP canary, not a supported deployment runtime. The
Leptos/browser dependency graph is locked to `wasm-bindgen` 0.2.126; that
browser binding version is independent of the WASI component ABI.

The workspace is intentionally split into small crates:

- `wasi-authz-contract`: bounded AuthZEN request and decision types.
- `wasi-authz-client`: transport-neutral PEP client with additive WASI HTTP transports.
- `wasi-authz-testkit`: provider conformance fixtures.
- `wasi-authz-http`: coarse HTTP route enforcement helpers.
- `wasi-authz-cedar`: embedded Cedar RBAC/ABAC provider.
- `wasi-authz-spicedb`: Zanzibar-style SpiceDB adapter.
- `leptos-wasi-authz`: typed Leptos request context and server-function integration.

The workspace also builds experimental, separately deployable final-WASIp3
coarse HTTP PEP, Cedar PDP, and SpiceDB PDP components. Production applications
embed Cedar and call SpiceDB directly through the typed provider; the remote
AuthZEN SpiceDB PDP remains a compatibility deployment.

This alpha does not cache authorization decisions. Unknown standard AuthZEN
members and null/empty collection obligations remain forward-compatible;
non-empty or malformed scalar obligations and unknown members inside the
documented `wasi_authz` extension fail closed.
Anything other than an explicit, valid allow decision is denied or unavailable.

Install the checksum-pinned SpiceDB and `zed` binaries and run the live
relationship matrix with:

```bash
make provider-tools
make test-spicedb-live
```

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

See [Architecture](docs/ARCHITECTURE.md),
[Compatibility](docs/COMPATIBILITY.md), [Production support](docs/SUPPORT.md),
[Security](SECURITY.md), [Relationship consistency](docs/CONSISTENCY.md), and
[Release process](docs/RELEASE.md).
