# wasi-http-authn

In-process authentication boundary for terminal WASI HTTP applications.

It supports explicit trusted-ingress and statically dispatched broker modes,
removes credentials and reserved identity headers before dispatch, and stores a
validated `VerifiedAuthContext` in `http::Extensions`.

Portable WASI component middleware remains available separately; this crate is
the production-oriented path that avoids immutable WASI header reconstruction.
