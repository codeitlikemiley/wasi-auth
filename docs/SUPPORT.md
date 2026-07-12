# Production support matrix

`0.1.0-rc.1` is a production release candidate. “Supported” below means the
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
| Spin main ordinary WASIp3 | Experimental canary | `4.1.0-pre0` revision `c34c584...` runs final terminal and outbound HTTP; no tagged support claim |
| Spin/Tonic gRPC over HTTP | Experimental canary | Unary plus server-, client-, and bidirectional-streaming reference tests pass on the pinned SDK/runtime graph; tagged-runtime promotion and soak remain pending |
| Spin HTTP middleware | Experimental and unavailable | Default main build panics for composed handlers; native middleware remains RC-only |
| Native trusted ingress | Production architecture; alpha promotion pending | Paired benchmark must remain within 10% throughput and p99 overhead |
| Cedar RBAC/ABAC | Default embedded provider | Schema activation, RBAC/ABAC conformance, and complete-chain concurrency-100 p99 gate |
| Cedar WASIp3 PDP | Experimental | Production terminal embeds the Cedar provider |
| SpiceDB ReBAC | Functional and opt-in; production promotion pending | Live SpiceDB 1.54.0/zed 1.1.1 matrix plus an unmet independent 25 ms p99 concurrency-100 gate |
| SpiceDB WASIp3 PDP | Compatibility profile | Production terminal calls SpiceDB directly; no extra AuthZEN service hop |
| Leptos islands/server functions | Companion support | Request context, route/server-function guards, declared-island hydration, and lazy-chunk browser checks |
| Decision cache | Unsupported | Every decision is evaluated |
| Non-empty or scalar obligations | Unsupported | Only null/empty array/object is ignored |
| Raw WebSockets/HTTP body streaming | Out of scope | Host/application responsibility; bounded Tonic gRPC streams are covered separately |
| Non-HTTP triggers | Contract only | A trigger-specific PEP is required |

Spin is deliberately not marked supported. Pinned Spin main now runs ordinary
final-WASI terminals and outbound HTTP, but tagged Spin 4.0.2 still lacks the
final resources. The default main build also panics for WAC-composed handlers,
while native middleware still hard-codes a release-candidate ABI. Promotion
requires a tagged Spin release that links the exact final WIT, fixes composed
handler CPU accounting, and passes HTTP, all four gRPC modes, browser flows,
five paired performance samples, and the ten-minute concurrency-100 soak.

Library stability and runtime deployment promotion are separate. A stable
contract/provider release does not imply that the blocked Spin profile or the
Wasmtime reference profile passed the production 25 ms concurrency-100 SLO.

The latest local Wasmtime 46.0.1 remote Cedar-PDP canary completed 1,000
requests at concurrency 100 with zero failures and 2,826.42 requests/s, but
measured 42.673 ms p99. It therefore fails the 25 ms gate. This single remote
PDP sample is diagnostic evidence only; it is not the required five-sample
embedded application benchmark or ten-minute soak.

The 2026-07-12 consolidated-source trusted-ingress matrix subsequently
completed all five repetitions, but every profile recorded an unexpected
status or transport outcome and only two of five paired anonymous-edge samples
met both 10% regression limits. A corrected 600.009-second, two-terminal soak
completed 2,586,955 responses at 4,311.53 responses/s with zero cancellations
or hangs and no final-quarter RSS breach, but recorded 1,005,636 unexpected
statuses, 42,793 transport failures, and 81.407 ms successful-response total
p99. Native trusted ingress, embedded Cedar, and direct SpiceDB therefore
remain unpromoted deployment profiles. The tracked diagnostic summary is
`reports/runtime/trusted-ingress-wasmtime-46.0.1-darwin-arm64-2026-07-12.json`;
its dirty-source marker means it is not signed release provenance.

The locked Leptos/browser graph uses `wasm-bindgen` 0.2.126. It does not
participate in the WASI component boundary and therefore does not change the
Spin or Wasmtime support status.

Host or ingress responsibilities remain: TLS termination, mTLS/PDP credentials,
global request deadlines, WAF, distributed rate limiting, circuit breaking,
revocation/JWKS caching, HSTS, and cookie/CSRF policy. CORS is not CSRF
protection.

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
