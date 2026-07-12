# wasi-auth

`wasi-auth` is the single public authentication, authorization, and trusted-
ingress crate for WASI services. It combines account and session lifecycles,
multi-tenant organizations, native HTTP security policy, embedded Cedar,
optional direct SpiceDB, Leptos context, and Spin gRPC request support behind
an empty-by-default feature graph.

Current version: `0.1.0-rc.1`.

The standalone crate baseline is Rust 1.93, `wasip3` 0.7.0 with final
`wasi:http@0.3.0`, and Wasmtime 46.0.1. Tagged Spin 4.0.2 cannot link the
final-WASI components. Spin consumers are pinned to SDK revision
`a02d330fe9357be2d18e6deef400511195ce6f7f` until a tagged upstream release contains
the required final-WASI and gRPC graph. That immutable SDK manifest declares
Rust 1.93. The maintained Spin runtime fork is pinned to
`c34c584dbf77b3a3528ad0536aa9ce4761b9f772`; it is the release-candidate
terminal lane, while WAC-composed middleware remains experimental. The
Leptos/browser dependency graph is locked to `wasm-bindgen` 0.2.126; that
browser binding version is independent of the WASI component ABI.

Exactly one library package is publishable: `wasi-auth`. The older
`wasi-authz-*` and `leptos-wasi-authz` packages remain private compatibility
fixtures while consumers migrate; portable PDP and middleware components are
also private workspace packages.

```toml
[dependencies]
wasi-auth = { version = "0.1.0-rc.1", default-features = false, features = [
  "fullstack-spin",
  "storage-postgres",
  "mail-smtp",
] }
```

Development templates use `storage-spin-sqlite` and `mail-capture` instead.
Production startup must select PostgreSQL and either SMTP or the documented
HTTP webhook adapter.

The workspace also builds experimental, separately deployable final-WASIp3
coarse HTTP PEP, Cedar PDP, and SpiceDB PDP components. Production applications
embed Cedar and call SpiceDB directly through the typed provider; the remote
AuthZEN SpiceDB PDP remains a compatibility deployment.

Production request handling uses native trusted ingress and installs one
non-forgeable `VerifiedAuthContext`. Guest-composed component middleware and
remote AuthZEN PDPs are compatibility features only. Embedded Cedar is the
default decision provider; SpiceDB calls are direct and opt-in. Anything other
than an explicit valid allow decision fails closed.

The publishable API is organized into `context`, `authentication`,
`authorization`, `http`, `cedar`, `spicedb`, `leptos`, `spin_grpc`, `ddd`,
`mail`, and `testkit`. `AuthApplicationBuilder` uses typestate so a store,
authorizer, mailer, secret store, clock, and randomness source are all required
at compile time. `AuthUnitOfWork` commits sanitized events, projections,
secret mutations, idempotency state, and mail or relationship outbox intents
as one bounded mutation; its test adapter proves rollback at every stage and
idempotent replay.

Install the checksum-pinned SpiceDB and `zed` binaries and run the live
relationship matrix with:

```bash
make provider-tools
make test-spicedb-live
```

See [Architecture](docs/ARCHITECTURE.md),
[Compatibility](docs/COMPATIBILITY.md), [Production support](docs/SUPPORT.md),
[Security](SECURITY.md), [Relationship consistency](docs/CONSISTENCY.md), and
[Release process](docs/RELEASE.md).
