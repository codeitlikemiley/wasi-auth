# Security policy

## Supported versions

`0.2.0-alpha.1` is an experimental final-WASI compatibility release, not a
stable support promise. Security fixes apply to the latest alpha on `main`;
older alpha artifacts are not maintained. The exact tuple in
`compatibility.toml` is part of the supported surface.

## Reporting

Do not open a public issue containing credentials, exploit details, or a live
deployment. Report privately to the maintainer address in `Cargo.toml` and
include artifact checksum, runtime tuple, minimal reproduction, and whether any
route reaches the terminal without the composed boundary.

## Deployment boundary

Before reporting an identity bypass, verify that every externally reachable
route passes through `authn-policy` or `secure-defaults`; the terminal must not
be exposed by a second trigger. The application must treat identity as the
ordered `(issuer, subject)` pair and keep resource/domain authorization inside
its own middleware.

`Authorization` and client `x-wasi-auth-*` values must be absent downstream.
`x-wasi-auth-context` must be absent from browser-facing responses. Ingress TLS,
host deadlines, static assets, distributed limits, and WebSocket policy remain
outside this component chain.

Current Spin hosts cannot link final WASI 0.3 artifacts. A deployment that
converts or downgrades these binaries to the March RC is outside the supported
security boundary.
