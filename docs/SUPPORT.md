# Production support matrix

`0.1.0-alpha.3` is a production-hardening alpha. “Supported” below means the
named contract has an executable release gate; it does not remove the alpha
stability warning.

| Surface | Alpha status | Release evidence |
|---|---|---|
| Bounded AuthZEN 1.0 contract | Supported | Golden, negative, property, and fuzz tests |
| Native Rust PEP/client | Supported | Rust 1.93 MSRV and current-stable lanes |
| WASIp2 decision client | Contract-supported; runtime promotion pending | Additive feature compile/test lane; injected pollable waiter is mandatory |
| WASIp3 decision client | Supported | `wasip3` 0.7.0/final `wasi:http@0.3.0` compile lane plus Wasmtime 46.0.1 lifecycle and recovery checks |
| WASIp3 coarse HTTP PEP | Contract-qualified; promotion pending | Exact WIT/capability allowlist passes; cross-repository E2E is required |
| Wasmtime | Reference version 46.0.1 | Final-WASI correctness, lifecycle, and recovery contract; no production latency claim |
| Spin 4.0.2 ordinary WASIp3 | Blocked upstream | Tagged host cannot link this final-WASI chain |
| Spin main ordinary WASIp3 | Experimental canary | `4.1.0-pre0` revision `c34c584...` runs final terminal and outbound HTTP; no tagged support claim |
| Spin HTTP middleware | Experimental and unavailable | Default main build panics for composed handlers; native middleware remains RC-only |
| Cedar RBAC/ABAC | Supported provider | Schema activation and RBAC/ABAC conformance fixtures |
| Cedar WASIp3 PDP | Experimental | Production terminal embeds the Cedar provider |
| SpiceDB ReBAC | Supported provider | Live SpiceDB 1.54.0 and zed 1.1.1 matrix |
| SpiceDB WASIp3 PDP | Compatibility profile | Production terminal calls SpiceDB directly; no extra AuthZEN service hop |
| Leptos server functions | Companion support | Request context, scope layer, and domain authorization tests |
| Decision cache | Unsupported | Every decision is evaluated |
| Non-empty or scalar obligations | Unsupported | Only null/empty array/object is ignored |
| WebSockets/request streaming | Out of scope | Host/application responsibility |
| Non-HTTP triggers | Contract only | A trigger-specific PEP is required |

Spin is deliberately not marked supported. Pinned Spin main now runs ordinary
final-WASI terminals and outbound HTTP, but tagged Spin 4.0.2 still lacks the
final resources. The default main build also panics for WAC-composed handlers,
while native middleware still hard-codes a release-candidate ABI. Promotion
requires a tagged Spin release that links the exact final WIT, fixes composed
handler CPU accounting, and contains final HTTP middleware composition.

Library stability and runtime deployment promotion are separate. A stable
contract/provider release does not imply that the blocked Spin profile or the
Wasmtime reference profile passed the production 25 ms concurrency-100 SLO.

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
