# Architecture

The stable boundary is the authorization request and decision contract, not a
policy language. A policy enforcement point (PEP) sends a bounded AuthZEN 1.0
request to a policy decision point (PDP). Providers translate the same typed
contract into Cedar, SpiceDB, or a remote HTTPS service.

```text
request -> PEP -> wasi-authz contract -> provider -> decision
             \-> application enforcement <-/
```

Only an explicit `decision: true` may proceed. A valid false decision is a
denial. Transport failure, malformed JSON, an unsupported mandatory
obligation, invalid `wasi_authz` metadata, and provider indeterminacy are
unavailable outcomes. Decision caching is deliberately unsupported in version
0.1.

The contract carries no credentials, cookies, authorization headers, request
bodies, or unrestricted JSON. Attributes are typed, bounded, and labeled with
their trusted provenance.

Authentication is an upstream middleware responsibility. The authorization
contract receives an explicit anonymous or authenticated subject; it never
verifies or forwards bearer credentials. HTTP admission is intentionally
coarse. Domain actions such as `order.update` are enforced after typed argument
deserialization and authoritative resource loading in the application.
