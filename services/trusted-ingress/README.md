# wasi-auth native trusted ingress

`wasi-auth-ingress` is the private native terminal for the supported Spin
deployment. It is released as a signed binary and OCI artifact while
`wasi-auth` remains the workspace's only publishable library crate.

The public listener authenticates bearer or host-cookie credentials using a
prepared native PostgreSQL pool. A bounded process cache is invalidated by
transactional `LISTEN/NOTIFY` events from migration
`0009_context_invalidation` and revalidated from storage every second as a
defense in depth. If the listener disconnects, cache reuse stops and requests
fall back to authoritative queries. The service refuses startup when any
required trigger is missing.

The active content-addressed Cedar bundle is loaded from PostgreSQL and
strictly validated. Policy publication advances the same invalidation epoch,
so the terminal reloads a stable committed revision before serving another
native authorization result. A missing active record selects the immutable
build-validated default; a malformed or unavailable active record fails
closed.

Authenticated requests receive an HMAC-SHA-256 context envelope bound to the
deployment audience, HTTP method, path, request ID, and a five-second replay
window. Spin must listen only on loopback or an equivalent private pod network;
production guest configuration rejects credential-bearing requests without a
valid envelope.

The direct Hyper terminal streams bodies and trailers without buffering,
preserving gRPC
unary, server-streaming, client-streaming, and bidirectional-streaming
backpressure. Bounded bearer REST checks at `/api/authorization/check` and
`/api/authorization/batch-check` execute Cedar directly from the same active
bundle used by the generated application.
SpiceDB-enabled deployments bypass this optimization and use the guest's full
provider chain.

Required environment variables:

- `DATABASE_URL` (`sslmode=require` is mandatory in production; rustls uses
  OS/container roots and honors `SSL_CERT_FILE` for private CAs)
- `AUTH_TRUSTED_INGRESS_KEY_BASE64` (exactly 32 decoded bytes)
- production `AUTH_JWT_KEY_RING_JSON` with ES256 material

Key defaults:

- `AUTH_INGRESS_LISTEN=127.0.0.1:3008`
- `AUTH_INGRESS_BACKEND_ORIGIN=http://127.0.0.1:3009`
- `AUTH_INGRESS_POSTGRES_POOL_SIZE=32`
- `AUTH_INGRESS_TOKEN_CACHE_CAPACITY=4096`
- `AUTH_INGRESS_CACHE_REVALIDATE_MS=1000`
- `AUTH_TRUSTED_INGRESS_AUDIENCE=fullstack-app`
- `AUTH_TRUSTED_INGRESS_MAX_AGE_SECONDS=5`

Apply and verify migrations before starting either process. Never expose the
Spin backend port or place the shared ingress key in the application manifest,
container image, logs, or source control.
