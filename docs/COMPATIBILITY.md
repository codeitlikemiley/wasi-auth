# Compatibility

| Surface | Status in `0.1.0-rc.3` |
|---|---|
| Rust | Library MSRV 1.99.0 |
| AuthZEN Authorization API | Final 1.0 bounded access-evaluation profile |
| Unknown standard members | Ignored as AuthZEN requires |
| `wasi_authz` extension | Strictly parsed and crate-versioned; unknown members rejected |
| Decision obligations | Null/empty array/object ignored; non-empty or scalar rejected fail-closed |
| Decision caching | Unsupported |
| Native Rust | Supported |
| WASIp2 outbound HTTP | Additive `wasip2` client feature with an injected cancellation-safe pollable waiter |
| WASIp3 outbound HTTP | Additive `wasip3` client feature using `wasip3` 0.9.0+wasi-0.3.0 and final `wasi:http@0.3.0` |
| Component bindings | `wit-bindgen` 0.62.0, exactly matching the runtime embedded by tagged `wasip3` 0.9.0+wasi-0.3.0 |
| Browser bindings | `wasm-bindgen` 0.2.126 in the locked Leptos/browser graph; unrelated to the WASI HTTP ABI |
| Wasmtime | `50.0.0`, final-WASI component contract |
| Spin 4.0.2 | Tagged compatibility canary; final-WASI linking is unavailable |
| Maintained Spin fork `c34c584...` (`4.1.0-pre0`) | Release-candidate final-WASI terminal/outbound-HTTP lane; WAC middleware remains experimental and no upstream tagged support is claimed |
| Spin SDK | Git revision `3cf30012b50a1afb750dac3d28aa6da4a32c3468` (SDK 7.0.0); Rust 1.99.0 toolchain |
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

## Companion surface

A downstream consumer such as `leptos_wasi` depends on this repository through
local path dependencies. Portable middleware crates are a separate git pin of
`codeitlikemiley/wasi-http-middleware`. Only `wasi-auth` is publishable from
this repository. Middleware crate version `0.2.0-alpha.3` stays on revision
`3df96c21a7906b885e67229e9a7c8c01b6497109` until `v0.2.0-alpha.4` is published.

[`companion.toml`](../companion.toml) is the machine-readable record of that
surface. It lists every crate a consumer may depend on with its resolved
version, owning workspace, and publishability; every built component with its
source directory, artifact path, SBOM, and WIT report; and the evidence a
release bundle carries. `scripts/generate-companion-manifest.sh` derives it from
`cargo metadata` for this workspace, and CI fails if the tracked copy drifts,
so a rename, a move, or a version bump cannot silently desynchronize a
consumer's lock.

The two kinds of path in that file resolve differently. Crate and component
paths are repository-relative and exist in a checkout. The evidence paths under
`[artifact]` — the checksum manifest, provenance statement, OCI manifest,
signatures, and signing key — name files in the release bundle, and are
git-ignored by design; they do not resolve in a checkout at any revision. A
consumer pins a revision for source and obtains the evidence from the bundle a
release run uploads.

The five path companion crates, marked `direct = true`, are
`leptos-wasi-authz`, `wasi-authz-cedar`, `wasi-authz-client`,
`wasi-authz-contract`, and `wasi-authz-spicedb`, all at the workspace version.
`wasi-http-authn` is also `direct = true` and is fetched from the middleware
git revision on its own `0.2.0-alpha.3` line. The two version lines are
independent; a consumer pins both.

`wasi-authz-http` and `wasi-authz-testkit` are path-local crates with
`direct = false`. `wasi-http-metadata` and `wasi-http-policy-core` are the
same git revision as `wasi-http-authn`, also `direct = false`. A consumer
should not name those four in its own manifest. The path crates must be
present in the checkout. The middleware crates are fetched by revision.
`wasi-http-metadata`'s types (`AuthContextV1`, `VerifiedAuthContext`, and
siblings) are re-exported through `leptos-wasi-authz`.

Native trusted ingress and the `wasi-auth` crate do not depend on these
middleware crates. The portable context is unsigned base64url JSON.
`decode_auth_context` and `accept_trusted_ingress` reject the dotted HMAC
envelope and do not verify the MAC. Portable security headers are `nosniff`
and `Referrer-Policy: strict-origin-when-cross-origin`. This crate's response
policy is `same-origin` plus CSP and HSTS. Those policies are different
owners. On this revision, `apply_response_security` and `CorsConfig::apply`
still insert their own values, so running both writers on one response
replaces `Referrer-Policy` and `nosniff` and can replace a CORS policy
already present. The production path does not call the portable helpers.
The non-overwrite guard is the separate signed-context change: it leaves a
response unchanged when a foreign referrer, CSP, nosniff, or HSTS value is
already present, and a second value for those headers or for CORS is a
failed response. Portable `apply_security_headers` still inserts, so it
replaces referrer and `nosniff` if it runs after that guard.
