# Migrating from 0.1.0-alpha.1 to 0.2.0-alpha.1

This is an intentional breaking alpha update. Do not mix 0.1 components,
bindings, policy payloads, or trusted headers with the 0.2 chain.

## Component and WIT changes

- Replace the `auth-policy` component with `authn-policy`.
- Rebuild every component against final `wasi:http@0.3.0`; the March 2026 RC
  handler/types/client interfaces are not composition-compatible with 0.2.
- Replace `WASI_MIDDLEWARE_POLICY_*` configuration with the documented
  `WASI_MIDDLEWARE_AUTHN_*`, immutable service ID, audience, admission, and
  loopback-development settings in `docs/CONFIGURATION.md`.
- Replace the `mock-policy` fixture with `mock-authn-broker`.

## Trusted identity contract

The loose `x-wasi-auth-subject`, `x-wasi-auth-issuer`, and
`x-wasi-auth-scopes` headers are removed. The authentication component strips
all inbound `x-wasi-auth-*` fields and injects one bounded, versioned
`x-wasi-auth-context` value containing `AuthContextV1`.

Applications must decode and validate `AuthContextV1`, verify its immutable
service/audience binding, and distinguish anonymous from authenticated
contexts. Never accept a trusted context on a route that can bypass the outer
authentication component.

## Rust API changes

`wasi-http-metadata` replaces `Principal`, `parse_principal`,
`insert_principal`, `AUTH_SUBJECT_HEADER`, `AUTH_ISSUER_HEADER`, and
`AUTH_SCOPES_HEADER` with the `ActorV1`/`PrincipalV1`/`AuthContextV1` contract
and encoded-context helpers. The old `MetadataError::InvalidIdentityValue`,
`MetadataError::InvalidScopes`, and `MetadataError::InvalidHeader` variants are
removed with that loose-header parser.

`wasi-http-policy-core` replaces `PolicyRequest`, `PolicySuccess`, and
`parse_policy_response` with the versioned authentication request/response
types. `AuthDecision::Forbidden` is removed: authentication owns 401 and
provider-unavailable 503 outcomes, while authenticated domain authorization
owns 403.

The checked-in semver report at
`reports/semver/0.1.0-alpha.1-to-0.2.0-alpha.1.md` records these intentional
breaks against baseline revision
`6977a75c4d2cb1558158341c109e419189dc2c52`.
