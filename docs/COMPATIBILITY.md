# Compatibility

| Surface | Status in `0.1.0-rc.1` |
|---|---|
| Rust | Library MSRV 1.93; async final-WASI component builds require Rust 1.94+ |
| AuthZEN Authorization API | Final 1.0 bounded access-evaluation profile |
| Unknown standard members | Ignored as AuthZEN requires |
| `wasi_authz` extension | Strictly parsed and crate-versioned; unknown members rejected |
| Decision obligations | Null/empty array/object ignored; non-empty or scalar rejected fail-closed |
| Decision caching | Unsupported |
| Native Rust | Supported |
| WASIp2 outbound HTTP | Additive `wasip2` client feature with an injected cancellation-safe pollable waiter |
| WASIp3 outbound HTTP | Additive `wasip3` client feature using `wasip3` 0.7.0 and final `wasi:http@0.3.0` |
| Component bindings | `wit-bindgen` 0.57.1, exactly matching the runtime embedded by tagged `wasip3` 0.7.0 |
| Browser bindings | `wasm-bindgen` 0.2.126 in the locked Leptos/browser graph; unrelated to the WASI HTTP ABI |
| Wasmtime | `46.0.1`, final-WASI component contract |
| Spin 4.0.2 | Tagged compatibility canary; final-WASI linking is unavailable |
| Maintained Spin fork `c34c584...` (`4.1.0-pre0`) | Release-candidate final-WASI terminal/outbound-HTTP lane; WAC middleware remains experimental and no upstream tagged support is claimed |
| Spin SDK | Git revision `a02d330fe9357be2d18e6deef400511195ce6f7f`; Rust 1.94 final-WASI component and Tonic gRPC lane |
| Cedar | Embedded provider and native reference PDP |
| SpiceDB | CheckPermission adapter tested with `1.54.0` |
| Leptos | Current 0.8 line, islands-compatible request/server-function helpers |
| Non-HTTP triggers | Reuse contract/provider; trigger-specific PEP required |

The AuthZEN specification permits extensions and requires unknown standard
members to be ignored. This project follows that rule outside its own reserved
namespace. Inside `wasi_authz`, strict parsing prevents unrecognized
enforcement instructions from crossing the trust boundary.

Exact versions and the imported middleware history revision live in
[`compatibility.toml`](../compatibility.toml). The authoritative operational
matrix is [Production support](SUPPORT.md).

The browser and component binding versions serve different targets.
`wasm-bindgen` supports the Leptos browser artifact, while `wit-bindgen` and
`wasip3` must resolve to one component runtime version. Upgrade `wit-bindgen`
only with a tagged `wasip3` release generated against that same version.
Together they define the component-facing final-WASI contract. Updating one is not
evidence that the other ABI or runtime lane is compatible.

## WASIp2 alpha API correction

The unpublished pre-release shape `Wasip2Transport::new()` used blocking
Preview 2 stream adapters and separate per-phase timeouts. It has intentionally
been removed. Construct the transport with the owning runtime's waiter instead:

```ignore
let transport = Wasip2Transport::new(LeptosPollableWaiter);
```

`LeptosPollableWaiter` implements `PollableWaiter` by delegating to
`leptos_wasi::wasip2::WaitPoll`; the complete adapter is in the transport's
Rustdoc. Other executors must provide equivalent cancellation-on-drop behavior.
There is no supported blocking compatibility constructor.

## WASIp3 component lifecycle

The WASIp3 transport constructs final-WASI request resources directly. It
concurrently drives body upload, the outbound send, and the transmission result
under one absolute deadline, then collects a bounded response and awaits and
discards provider trailers before declaring the exchange complete. It does not
depend on a second executor hidden inside `http_compat`.

Response metadata is fail-closed: duplicate headers are preserved, sensitive
headers are marked sensitive, and `Content-Length` must be one decimal value
that is within the response limit and exactly matches the collected body.
Malformed, duplicate, oversized, or mismatched lengths are protocol failures.
Host error strings are never returned through the transport error surface.
