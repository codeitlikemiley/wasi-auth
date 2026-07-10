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
denial. Transport failure, malformed JSON, unsupported decision context, and
provider indeterminacy are unavailable outcomes. Decision obligations and
caching are deliberately unsupported in version 0.1.

The contract carries no credentials, cookies, authorization headers, request
bodies, or unrestricted JSON. Attributes are typed, bounded, and labeled with
their trusted provenance.
