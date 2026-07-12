# Native outbox worker

`wasi-auth-outbox-worker` is the required production delivery process. The
Spin guest commits mail and relationship intents to PostgreSQL and returns;
it never calls either provider from an HTTP, REST, gRPC, or Leptos request.

Install the binary from the exact same `wasi-auth` release as the application:

```bash
cargo install wasi-auth --version 0.1.0-rc.1 \
  --features outbox-worker --bin wasi-auth-outbox-worker
```

Required settings:

| Setting | Contract |
|---|---|
| `DATABASE_URL` | PostgreSQL URL; production requires `sslmode=require` |
| `AUTH_PRODUCTION_MODE` | Strict `true`/`false`; defaults to development |
| `AUTH_PUBLIC_BASE_URL` | HTTPS origin in production; loopback HTTP in development |
| `AUTH_OUTBOX_KEY_BASE64` | Dedicated 32-byte mail-outbox key, shared with the app |
| `AUTH_OUTBOX_KEY_VERSION` | Non-empty version, shared with the app |
| `AUTH_MAIL_TRANSPORT` | `http` in production; `capture` is development-only |
| `AUTH_MAIL_HTTP_URL` | HTTPS webhook endpoint when HTTP mail is selected |
| `AUTH_MAIL_HTTP_TOKEN` | Mail webhook bearer credential |

Optional SpiceDB synchronization is enabled with
`AUTH_SPICEDB_ENABLED=true`, which also requires
`AUTH_SPICEDB_WRITE_URL=/v1/relationships/write` and
`AUTH_SPICEDB_TOKEN`. These write credentials belong only to the worker. The
request component uses a separate check-only credential.

The pool size, mail batch, relationship batch, and poll interval are bounded
by `AUTH_OUTBOX_POSTGRES_POOL_SIZE` (`1..=32`),
`AUTH_OUTBOX_MAIL_BATCH_SIZE` (`1..=25`),
`AUTH_OUTBOX_RELATIONSHIP_BATCH_SIZE` (`1..=100`), and
`AUTH_OUTBOX_POLL_INTERVAL_MS` (`100..=60000`). Provider redirects are
disabled, requests have finite connect/total deadlines, and response bodies
are collected only up to the adapter limit.

Run one or more replicas. `FOR UPDATE SKIP LOCKED` prevents duplicate active
leases, while idempotent provider operations make retry after a lost database
acknowledgement safe. Relationship rows for one tuple are leased in revision
order. A dead-letter relationship remains fail-closed for its resource until
an operator resolves or deliberately supersedes it.

Production startup rejects capture mail, loopback/non-TLS origins, non-TLS
PostgreSQL, incomplete SpiceDB configuration, malformed bounds, missing keys,
and the documented development outbox key. Logs contain categories and counts,
not provider responses, recipient data, tokens, URLs, or database credentials.
