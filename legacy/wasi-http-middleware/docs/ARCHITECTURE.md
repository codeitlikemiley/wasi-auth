# Architecture

## Composition model

Every portable middleware component imports and exports
`wasi:http/handler@0.3.0`.
WAC wires the terminal handler into each middleware at build time; there is no
sidecar process or network hop between middleware and the application.

```text
client
  -> request-id
  -> security-headers
  -> cors
  -> authn-policy
  -> terminal service
```

`secure-defaults` implements the same order in one component. Requests flow
inward and responses unwind outward, so CORS preflight precedes authentication
and request/security headers decorate controlled rejections.

## Crate boundaries

- `wasi-http-policy-core` contains pure request-ID, header, CORS, broker-response,
  and defensive path utilities.
- `wasi-http-metadata` owns the bounded `AuthContextV1` wire contract.
- `wasi-http-authn-runtime` validates broker configuration and owns broker I/O,
  deadlines, cancellation, and in-flight admission.
- `wasi-http-middleware-component-support` preserves message resources while
  applying header diffs.
- `components/*` exports standard middleware components only.
- `test-components/*` and `passthrough` are conformance fixtures, not production
  identity services.

The shared metadata and component-support crates are ordinary Rust library APIs.
Portable components contain no Leptos or Spin SDK dependency. Production
deployments use the shared policy and metadata crates in a trusted native
ingress; guest components remain experimental.

## Streaming invariant

Application request and response bodies are never collected by middleware.
Header replacement transfers the original body and body-result resources. Each
wrapper relays the new message's `transmission_result` into the original
`consume_body` result; discarding either future can cancel an upstream producer
and lose the first frame when a stream immediately fails.

Regression coverage repeats an observably mid-stream sequence `first frame ->
stream close -> body-result error` through stacked components and requires
every response that committed headers to deliver the first frame before the
error. A separate immediate body-result error must not hang or report success;
it does not require a buffered frame to beat connection termination. Delayed
streams, trailers, disconnects, request bodies, and failing streams are also
covered. Malformed header blocks rejected by the host before guest invocation
cannot be made equivalent by middleware and are treated as a host boundary.

The authentication request JSON is bounded control-plane data. Broker response
bodies are buffered to at most 64 KiB; application bodies remain streaming.

## Authentication versus authorization

`authn-policy` verifies a credential and emits one request-only context. The
broker receives no route, method, authority, query, cookie, or body. The
application receives no `Authorization` header. It uses the canonical
`(issuer, subject)` pair and claims for domain authorization. In Leptos this
belongs in `ServerFn::middlewares()`, where resource ownership and business
rules are available.

Ingress still owns TLS, HSTS, WAF policy, proxy identity, distributed limits,
global deadlines, and static asset controls. `/pkg/...` split-Wasm assets stay
public unless the CDN/fileserver/ingress explicitly protects them.

## Host and trigger boundary

Wasmtime 46.0.1 runs the final WASI 0.3 behavioral suite. Tagged Spin 4.0.2
lacks final `wasi:http@0.3.0` resource implementations. Pinned Spin main
`c34c584` (`4.1.0-pre0`) runs the final terminal and outbound HTTP, but its
default CPU-metrics hook panics for WAC-composed handlers. A
no-default-features build proves the composition path only as a diagnostic;
the pinned native-middleware commit still targets the March RC. These remain
distinct compatibility canaries rather than one broad Spin support claim.

HTTP middleware cannot wrap Redis, MQTT, cron, or custom triggers because they
export different WIT worlds. Future adapters may reuse pure policy crates, but
each adapter needs its own capability, lifecycle, and compatibility contract.
