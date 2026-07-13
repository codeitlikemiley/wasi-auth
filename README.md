# wasi-auth

`wasi-auth` is the single public authentication, authorization, and trusted-
ingress crate for WASI services. It combines account and session lifecycles,
multi-tenant organizations, native HTTP security policy, embedded Cedar,
optional direct SpiceDB, Leptos context, and Spin gRPC request support behind
an empty-by-default feature graph.

Current version: `0.1.0-rc.2`.

The standalone crate baseline is Rust 1.93, `wasip3` 0.7.0 with final
`wasi:http@0.3.0`, and Wasmtime 46.0.1. Tagged Spin 4.0.2 cannot link the
final-WASI components. Spin consumers are pinned to SDK revision
`a02d330fe9357be2d18e6deef400511195ce6f7f` until a tagged upstream release contains
the required final-WASI and gRPC graph. That immutable SDK manifest declares
Rust 1.93. The maintained Spin runtime fork is pinned to
`c34c584dbf77b3a3528ad0536aa9ce4761b9f772`; it is the release-candidate
terminal lane, while WAC-composed middleware remains experimental. The
library and SDK MSRV is Rust 1.93; the native Spin host requires Rust 1.94
because its Wasmtime 46 dependency graph declares that floor. The
Leptos/browser dependency graph is locked to `wasm-bindgen` 0.2.126; that
browser binding version is independent of the WASI component ABI.

Exactly one library package is publishable: `wasi-auth`. The older
`wasi-authz-*` and `leptos-wasi-authz` packages remain private compatibility
fixtures while consumers migrate; portable PDP and middleware components are
also private workspace packages.

```toml
[dependencies]
wasi-auth = { version = "0.1.0-rc.2", default-features = false, features = [
  "fullstack-spin",
  "postgres-spin",
] }
```

Development templates use PostgreSQL and `mail-capture`. Production startup
selects PostgreSQL while the native worker owns the first-class Resend or
provider-neutral HTTP webhook adapter and optional SpiceDB writes. Provider
credentials never enter the Spin guest. Install the worker from the same
package:

```bash
cargo install wasi-auth --version 0.1.0-rc.2 \
  --features outbox-worker --bin wasi-auth-outbox-worker
```

The workspace also builds experimental, separately deployable final-WASIp3
coarse HTTP PEP, Cedar PDP, and SpiceDB PDP components. Production applications
embed Cedar and call SpiceDB directly through the typed provider; the remote
AuthZEN SpiceDB PDP remains a compatibility deployment.

Production request handling uses native trusted ingress and installs one
non-forgeable `VerifiedAuthContext`. Guest-composed component middleware and
remote AuthZEN PDPs are compatibility features only. Embedded Cedar is the
default decision provider; SpiceDB calls are direct and opt-in. Anything other
than an explicit valid allow decision fails closed.

The private `wasi-auth-ingress` service is distributed as a signed binary/OCI
artifact, not as a second public crate. It terminates public HTTP, REST, and
gRPC traffic, validates credentials through a prepared native PostgreSQL pool,
and sends the loopback-only Spin backend a five-second HMAC envelope bound to
audience, method, path, and request ID. Migration
`0009_context_invalidation` publishes transactional cache invalidations; the
ingress refuses startup if the trigger set is incomplete. The default REST
Cedar check executes in the ingress from the same strictly validated policy
bundle, removing an unnecessary second HTTP hop. See
[Native trusted ingress](services/trusted-ingress/README.md).

Authentication is implemented by the PostgreSQL relational command kernel.
Each product mutation is one bounded, parameterized SQL statement that owns
its row locks, optimistic checks, credential changes, idempotency result,
authorization revision, audit record, and durable outbox insertion. It is not
event sourced. DDD business aggregates remain consumer concerns; `wasi-auth`
has no `ddd_cqrs_es` dependency.

Mail and optional SpiceDB delivery share `auth_outbox`. Mail payloads remain
encrypted; relationship rows use typed, non-secret relational metadata. The
native worker leases bounded batches with `FOR UPDATE SKIP LOCKED`, retries,
dead-letters poison records, and acknowledges provider delivery tokens.
Delivery no longer depends on request traffic.

The outbox worker is not an email server. Resend or the configured HTTP
provider remains the email service; `wasi-auth-outbox-worker` is the native
process that reads durable delivery intents from PostgreSQL and calls that
service. A registration request commits the account change and encrypted mail
intent together, returns without waiting for the provider, and lets the worker
record `pending`, `leased`, `delivered`, retry, or `dead_letter` state. If the
worker is stopped, no intent is lost: jobs remain pending until a worker is
started again. Provider credentials stay in the worker environment and never
enter the Spin guest.

Run the worker beside every production Spin deployment. For a local fullstack
application, `make dev` starts the worker automatically; running only `make
spin` starts the request component but cannot deliver email. Use separate
`make spin` and `make outbox-worker` terminals only when independent logs are
needed.

Install the checksum-pinned SpiceDB and `zed` binaries and run the live
relationship matrix with:

```bash
make provider-tools
make test-spicedb-live
```

See [Architecture](docs/ARCHITECTURE.md),
[Compatibility](docs/COMPATIBILITY.md), [Production support](docs/SUPPORT.md),
[Native outbox worker](docs/OUTBOX_WORKER.md),
[Performance](docs/PERFORMANCE.md),
[Security](SECURITY.md), [Relationship consistency](docs/CONSISTENCY.md), and
[Release process](docs/RELEASE.md).
