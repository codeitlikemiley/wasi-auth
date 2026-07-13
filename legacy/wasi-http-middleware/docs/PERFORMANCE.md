# Performance and soak evidence

## Reproducible commands

`benchmark-components.sh` runs three warmed Wasmtime 46 samples for the
unwrapped echo service, pass-through, request-ID, and security-header profiles.
It records JSON under `reports/performance/` and flags the historical
five-percent budget without failing the release. The tiny echo service measures
raw component-boundary overhead; it is not an application capacity forecast or
the stable-promotion gate.

```bash
bash scripts/benchmark-components.sh
```

The final local 2026-07-10 run at 20,000 requests and concurrency 100 measured:

| Profile | Median requests/s | Throughput regression | Median p99 | p99 regression |
|---|---:|---:|---:|---:|
| Pass-through | 46,504 | 21.8% | 8.40 ms | 68.7% |
| Request ID | 38,531 | 35.2% | 9.85 ms | 97.8% |
| Security headers | 53,108 | 10.7% | 6.03 ms | 21.1% |

The unwrapped baseline was 59,454 requests/s with 4.98 ms p99. These results
remain visible because the boundary is not free; host load and machine policy
still make them diagnostic rather than portable capacity claims.

Blocking performance acceptance runs in the sibling `leptos_wasi` integration
against its realistic SSR/server-function/static workload. The fused
`secure-defaults` profile may regress median throughput or p99 by at most ten
percent versus that same workload unwrapped. Stable promotion remains blocked
if either realistic measurement misses.

The 2026-07-10 five-pair, 30-second, concurrency-100 representative run first
measured an unwrapped Leptos service against the fused component. After the
component was changed to parse only policy-relevant fields and apply exact
edits directly to one cloned WASI header resource, the repeated gate still
failed with zero request errors:

| Metric | Unwrapped median | Fused median | Change | Budget |
|---|---:|---:|---:|---:|
| First-byte p99 | 7.961 ms | 12.527 ms | +57.36% | <= +10% |
| Total p99 | 8.934 ms | 13.578 ms | +51.98% | <= +10% |
| Throughput | 32,131.58 requests/s | 22,787.77 requests/s | -29.08% | >= -10% |

A separate realistic pass-through control stayed inside the same budget:
throughput -1.62%, first-byte p99 -5.65%, and total p99 -8.85%. The current
promotion blocker is therefore not the component boundary alone. It is the
immutable request and response header reconstruction plus transmission-result
bridging needed to inject trusted request metadata and mandatory response
headers without losing bodies, trailers, cancellation, or post-commit errors.
The threshold remains unchanged and the release remains alpha.

`soak-runtime.sh` runs the complete authenticated chain with a default ten
minutes, 100 concurrent clients, and 100 requests per second. It rejects client
errors, unexpected statuses, sensitive log values, and sustained second-half
RSS growth.

```bash
HOST=wasmtime bash scripts/soak-runtime.sh
```

Spin soak remains non-promoting. Tagged Spin 4.0.2 lacks final
`wasi:http@0.3.0` resources; pinned Spin main `c34c584` (`4.1.0-pre0`)
runs plain final terminals and outbound HTTP, but its default CPU-metrics hook
panics for composed handlers, and native middleware remains RC-only. A
no-default-features diagnostic is not endurance evidence, so no Spin result is
currently used to promote the portable middleware performance claim.

## Streaming performance invariant

Middleware copies bounded headers but never collects application bodies.
Delayed first bytes must arrive before a stream finishes. A first frame
followed by a short observable interval and a body-result error is repeated
through stacked middleware; every response that commits headers must preserve
the first frame, then expose the terminal error. A separate immediate-error
case requires cancellation without a hang or false success but does not assume
socket delivery won its scheduler race. The sibling Leptos transport suite
also verifies the relay with an observable mid-stream failure.

## Alpha promotion status

The raw five-percent budget remains a visible historical diagnostic. A local
smoke run may use reduced request/duration values to validate tooling, but it is
not substitute evidence for the default benchmark, the sibling realistic
ten-percent gate, or ten-minute soak. Generated JSON remains local because host
load, CPU policy, and background activity make it non-portable.
