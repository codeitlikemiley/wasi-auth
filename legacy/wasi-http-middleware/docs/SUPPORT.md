# Support matrix

This matrix describes `0.2.0-alpha.3`; it is not a stable-support promise.

| Capability | Status | Notes |
|---|---|---|
| Rust MSRV | Tested | Exact Rust 1.93.0 quality-gate toolchain |
| Final WASI 0.3 HTTP middleware | Alpha | Exact `wasi:http/middleware@0.3.0` |
| `wasip3` / `wit-bindgen` | Tested | `wasip3` 0.7.0 with `wit-bindgen` 0.59.0 |
| Rust build target | Build detail | `wasm32-wasip2` emits the component; public ABI is WASI 0.3 |
| Wasmtime 46.0.1 | Behavioral host | Composition, security, streaming, parity, concurrency, and soak runners |
| Spin 4.0.2 | Unsupported canary | Missing final `wasi:http@0.3.0` host resource implementations |
| Spin main `c34c584...` (`4.1.0-pre0`) terminal | Experimental canary | Final terminal and outbound HTTP work; exact untagged commit, not a support claim |
| Spin main WAC composition | Blocked upstream | Default CPU-metrics hook panics; no-default-features build is diagnostic only |
| Spin revision `27451471...` | Unsupported canary | Native middleware remains March-RC WIT and cannot compose final components |
| WAC-precomposed final chain on Spin | Experimental, blocked | Requires a tagged host plus the composed-handler CPU-accounting fix |
| `wasm-bindgen` 0.2.126 | Sibling browser test only | Not used by this server-component workspace or its public ABI |
| Other final-WASI hosts | ABI candidate | Must pass the complete contract before a support claim |
| Separate four-component chain | Implemented | Request ID, security, CORS, strict authn |
| Fused `secure-defaults` | Experimental | Golden-equivalent portable interoperability and conformance fixture |
| In-process `wasi-http-authn` | Alpha | Trusted-ingress and terminal-broker boundary using typed request extensions |
| Request/response streaming | Implemented | No application-body collection |
| Mid-stream frame then error | Implemented | First frame preserved before terminal error; separate immediate-error no-hang gate |
| Trailers | Forwarded, host-dependent | Attached to body-result future; client exposure depends on host protocol bridge |
| CORS preflight | Implemented | Exact allowlists; executes before authn |
| Required/optional authn | Implemented | Optional applies only to absent credentials |
| Versioned trusted context | Implemented | Bounded request-only base64url V1 envelope |
| Domain authorization | Application-owned | E.g. Leptos `ServerFn::middlewares()` |
| Disconnect/concurrency | Covered | Wasmtime recovery and concurrent-request contracts |
| Islands/split Wasm | Sibling integration | `leptos_wasi`; `/pkg/...` remains public at static boundary |
| WebSockets/upgrades | Not claimed | No component conformance coverage |
| WASIp2 HTTP middleware | Unsupported | Different synchronous handler contract |
| Redis/MQTT/cron/custom triggers | Unsupported | Require trigger-specific adapters |
| Static/range/cache policy | Out of scope | Fileserver/CDN/ingress responsibility |
| Distributed rate limiting | Out of scope | Requires shared host/service state |

Malformed host header blocks may be rejected before guest invocation and are
not a middleware parity surface. The authn broker is never sent method, path,
query, authority, cookies, or application body.

Stable promotion requires a final-WASI Spin host (if Spin support is claimed),
blocking performance budgets, signed release provenance under an approved CI
identity, scheduled memory plateau evidence, and no skipped production path.
The exact version evidence and commands are recorded in
[Tested compatibility](COMPATIBILITY.md).
