# Production support matrix

`0.1.0-rc.2` is a production release candidate. “Supported” below means the
named contract has an executable release gate; stable promotion still requires
the complete default-profile matrix.

| Surface | RC status | Release evidence |
|---|---|---|
| Bounded AuthZEN 1.0 contract | Supported | Golden, negative, property, and fuzz tests |
| Native Rust PEP/client | Supported | Rust 1.93 MSRV and current-stable lanes |
| WASIp2 decision client | Contract-supported; runtime promotion pending | Additive feature compile/test lane; injected pollable waiter is mandatory |
| WASIp3 decision client | Supported | `wasip3` 0.7.0/final `wasi:http@0.3.0` compile lane plus Wasmtime 46.0.1 lifecycle and recovery checks |
| WASIp3 coarse HTTP PEP | Contract-qualified; promotion pending | Exact WIT/capability allowlist passes; cross-repository E2E is required |
| Wasmtime | Reference version 46.0.1 | Final-WASI correctness, lifecycle, and recovery contract; no production latency claim |
| Spin 4.0.2 ordinary WASIp3 | Blocked upstream | Tagged host cannot link this final-WASI chain |
| Maintained Spin final-WASI fork | RC production profile | `4.1.0-pre0` revision `c34c584...` passes final HTTP, browser, all four gRPC modes, performance, and soak gates |
| Spin/Tonic gRPC over HTTP | RC supported on maintained fork | Unary plus server-, client-, and bidirectional-streaming tests pass through the exact native HTTP/2 terminal |
| Spin HTTP middleware | Experimental and unavailable | Default main build panics for composed handlers; native middleware remains RC-only |
| Native trusted ingress | RC production profile | Five protected-path pairs, five 60-second absolute samples, bounded revocation, and the ten-minute concurrency-100 soak pass |
| Cedar RBAC/ABAC | Default production provider | Active bundles reload on transactional invalidation; complete-chain worst p99 is 10.847 ms at concurrency 100 |
| Cedar WASIp3 PDP | Experimental | Production terminal embeds the Cedar provider |
| SpiceDB ReBAC | Transactional synchronization complete; production performance remains preview | Membership changes atomically emit resource-scoped typed intents and the native worker preserves tuple order; the independent 25 ms p99 gate remains open |
| SpiceDB WASIp3 PDP | Compatibility profile | Production terminal calls SpiceDB directly; no extra AuthZEN service hop |
| Leptos islands/server functions | Companion support | Request context, route/server-function guards, declared-island hydration, and lazy-chunk browser checks |
| Decision cache | Deliberately absent | Every Cedar decision is evaluated; only verified auth context is cached, transactionally invalidated, and revalidated within one second |
| Non-empty or scalar obligations | Unsupported | Only null/empty array/object is ignored |
| Raw WebSockets/HTTP body streaming | Out of scope | Host/application responsibility; bounded Tonic gRPC streams are covered separately |
| Non-HTTP triggers | Contract only | A trigger-specific PEP is required |

Upstream tagged Spin is deliberately not marked supported. Tagged Spin 4.0.2
still lacks the final resources, and component-composed handlers remain an
independent experimental profile. The maintained fork at `c34c584...` is the
RC production terminal because it passes the exact final WIT, HTTP, browser,
all four gRPC modes, five paired protected-path samples, five absolute samples,
and the ten-minute concurrency-100 soak. It can be replaced by an upstream tag
only after that tag passes the identical matrix.

The publishable library and pinned Spin SDK retain Rust 1.93 MSRV. The
maintained native Spin host truthfully declares Rust 1.94 because Wasmtime 46
and Cranelift 0.133 require it; release binaries may be built with a newer
stable compiler after the 1.94 floor lane passes.

Library stability and runtime deployment promotion are separate. A stable
contract/provider release does not imply that the blocked Spin profile or the
Wasmtime reference profile passed the production 25 ms concurrency-100 SLO.

The latest local Wasmtime 46.0.1 remote Cedar-PDP canary completed 1,000
requests at concurrency 100 with zero failures and 2,826.42 requests/s, but
measured 42.673 ms p99. It therefore fails the 25 ms gate. This single remote
PDP sample is diagnostic evidence only; it is not the required five-sample
embedded application benchmark or ten-minute soak.

The earlier consolidated-source matrix failed because it measured a
guest-composed multi-hop path with transport errors. That result remains useful
diagnostic history in
`reports/runtime/trusted-ingress-wasmtime-46.0.1-darwin-arm64-2026-07-12.json`
but no longer represents the supported architecture. The reimplemented native
terminal evaluates the same protected operation 4.83 times faster than direct
guest verification in the paired median. Its exact final binary completed five
60-second samples at 24,501.972 median requests/s and 10.847 ms worst p99, then
a ten-minute sample at 24,838.391 requests/s and 10.278 ms p99 with zero status
or transport failures, zero sensitive-log findings, bounded HTTP 401
revocation, and no second-half memory growth. See [Performance](PERFORMANCE.md).

The locked Leptos/browser graph uses `wasm-bindgen` 0.2.126. It does not
participate in the WASI component boundary and therefore does not change the
Spin or Wasmtime support status.

Deployment responsibilities remain: public TLS termination, optional mTLS,
global request deadlines, WAF, distributed rate limiting, circuit breaking,
HSTS, and deployment-specific capacity testing. Native ingress owns verified
context caching and revocation invalidation; the application owns cookie and
CSRF policy. CORS is not CSRF protection.

The WASIp2 client intentionally has no blocking or implicit executor. Its
`Wasip2Transport::new(waiter)` constructor requires the application runtime's
cancellation-safe `PollableWaiter`; `leptos_wasi::wasip2::WaitPoll` is the
documented Leptos adapter. One monotonic deadline covers request upload,
response headers, and body collection. Promotion still requires a Wasmtime
fault-injection check proving timeout/cancellation cleanup with real host
resources.

The WASIp3 client owns the complete host-resource lifecycle for each decision.
One deadline covers upload, send, transmission completion, bounded response
collection, and trailer disposal. The release candidate passed concurrent
composed Wasmtime 46 recovery testing; the final tracked component artifacts
must repeat that check during the cross-repository release gate.
