# Native outbox worker

`wasi-auth-outbox-worker` is the required production delivery process. It is
not an email server and it does not replace Resend or an HTTP mail provider.
It is a native background process that reads durable delivery intents from
PostgreSQL and calls the configured provider. The Spin guest commits mail and
relationship intents and returns; it never calls either provider from an HTTP,
REST, gRPC, or Leptos request.

The lifecycle is:

```text
request -> one PostgreSQL transaction
           account change + encrypted mail intent
        -> response
worker  -> lease pending intent -> provider API -> delivery ID/status
```

This makes provider failures and worker restarts recoverable. A stopped worker
leaves jobs as `pending`; a later worker retries them. A failed job eventually
becomes `dead_letter` and requires operational review. The worker also handles
optional SpiceDB relationship delivery, so authorization grants remain
fail-closed until their relationship write is confirmed.

Install the binary from the exact same `wasi-auth` release as the application:

```bash
cargo install wasi-auth --version 0.1.0-rc.2 \
  --features outbox-worker --bin wasi-auth-outbox-worker
```

Start it with the same PostgreSQL URL, outbox key, and key version used by the
application:

```bash
DATABASE_URL='postgres://...' \
AUTH_OUTBOX_KEY_BASE64='...' \
AUTH_OUTBOX_KEY_VERSION='production-v1' \
AUTH_MAIL_TRANSPORT=resend \
AUTH_RESEND_API_KEY='re_...' \
AUTH_RESEND_FROM='Workspace <auth@example.com>' \
wasi-auth-outbox-worker
```

The example `make dev` target supplies these variables automatically from
`.env`; the command above is for direct process supervision or production
containers. Never print the command with secrets expanded in deployment logs.

Required settings:

| Setting | Contract |
|---|---|
| `DATABASE_URL` | PostgreSQL URL; production requires `sslmode=require` |
| `AUTH_PRODUCTION_MODE` | Strict `true`/`false`; defaults to development |
| `AUTH_PUBLIC_BASE_URL` | HTTPS origin in production; loopback HTTP in development |
| `AUTH_OUTBOX_KEY_BASE64` | Dedicated 32-byte mail-outbox key, shared with the app |
| `AUTH_OUTBOX_KEY_VERSION` | Non-empty version, shared with the app |
| `AUTH_MAIL_TRANSPORT` | `resend` or `http` in production; `capture` is development-only |
| `AUTH_MAIL_HTTP_URL` | HTTPS webhook endpoint when HTTP mail is selected |
| `AUTH_MAIL_HTTP_TOKEN` | Mail webhook bearer credential |
| `AUTH_RESEND_API_KEY` | Resend sending API key when Resend is selected |
| `AUTH_RESEND_FROM` | Verified sender, for example `Workspace <auth@example.com>` |

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

The Resend adapter calls `POST https://api.resend.com/emails` directly. It
sends bounded plain-text transactional mail and uses the durable outbox
correlation ID as `Idempotency-Key`; the returned Resend email ID becomes the
stored delivery ID. Keep `AUTH_RESEND_API_KEY` only in the native worker
environment. The Spin guest does not need or receive it.

Run one or more replicas. `FOR UPDATE SKIP LOCKED` prevents duplicate active
leases, while idempotent provider operations make retry after a lost database
acknowledgement safe. Relationship rows for one tuple are leased in revision
order. A dead-letter relationship remains fail-closed for its resource until
an operator resolves or deliberately supersedes it.

For a local fullstack app, use the combined target:

```bash
make dev
```

This starts Spin and the worker together. Use these separate targets only when
you need independent logs or independent process supervision:

```bash
make spin
make outbox-worker
```

Running only `make spin` serves the application but does not deliver email.
Running only the worker delivers queued jobs but does not serve HTTP, REST,
gRPC, or Leptos pages.

Production startup rejects capture mail, loopback/non-TLS origins, non-TLS
PostgreSQL, incomplete SpiceDB configuration, malformed bounds, missing keys,
and the documented development outbox key. Logs contain categories and counts,
not provider responses, recipient data, tokens, URLs, or database credentials.
