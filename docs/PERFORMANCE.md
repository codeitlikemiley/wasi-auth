# Performance and soak evidence

The default RC profile is native trusted ingress, the maintained final-WASI
Spin runtime, PostgreSQL, and embedded Cedar. The 2026-07-12 local promotion
run passed the protected-path overhead, absolute p99, revocation, ten-minute
soak, memory-growth, and log-redaction gates.

## Correct comparison boundary

The paired gate compares the same bearer-protected authorization request and
database state in two modes:

1. direct Spin verifies the token, loads PostgreSQL context, and evaluates
   Cedar in the guest; and
2. native trusted ingress verifies the token, uses transactionally invalidated
   context, and evaluates the same Cedar bundle before the Spin boundary.

An anonymous page proxy is retained only as a diagnostic. It measures an extra
network hop while doing no authentication work, so it is not evidence for or
against the auth architecture. The protected comparison is the release gate.

| Gate | Result |
|---|---:|
| Five paired protected samples, concurrency 100 | Passed all five |
| Median throughput regression | −382.639% (about 4.83× faster) |
| Median p99 regression | −76.980% |
| Five 60-second absolute samples, concurrency 100 | Passed all five |
| Median throughput | 24,501.972 requests/s |
| Worst absolute p99 | 10.847 ms (limit 25 ms) |
| Ten-minute soak throughput | 24,838.391 requests/s |
| Ten-minute soak p99 | 10.278 ms |
| Unexpected statuses / transport failures | 0 / 0 |
| Soak revocation propagation | HTTP 401 in 62.845 ms |
| Second-half RSS growth | ingress 0 KiB; Spin −29,536 KiB |
| Sensitive-log findings | 0 |

The exact final terminal also preserved gRPC unary, server-streaming,
client-streaming, and bidirectional-streaming behavior through the native
HTTP/2 listener. The fullstack authorization capability request passed through
the same listener with a maximum batch size of 100.

The machine was an Apple M1 Pro with 16 GiB RAM, Rust 1.95.0, PostgreSQL
14.20, and maintained Spin `4.1.0-pre0` at `c34c584d`. Traffic and PostgreSQL
were loopback-local. Public TLS, load-balancer latency, and managed-database
network latency are deployment-specific and must be requalified without
changing these gates.

Machine-readable evidence, artifact hashes, every paired sample, and explicit
limitations are recorded in
[`reports/runtime/native-ingress-spin-postgres-cedar-darwin-arm64-2026-07-12.json`](../reports/runtime/native-ingress-spin-postgres-cedar-darwin-arm64-2026-07-12.json).

Generated consumers expose three deterministic gates:

```bash
bash scripts/benchmark_ingress_overhead.sh
bash scripts/benchmark_fullstack.sh
INGRESS_PID=<pid> SPIN_PID=<pid> bash scripts/soak_fullstack.sh
```

The overhead script requires a direct guest baseline on port 3010 and the
supported native terminal on port 3008. It provisions and revokes independent
accounts for each alternating-order pair. The absolute and soak scripts prove
HTTP status, transport, p99, bounded revocation, memory, and log-redaction
outcomes and exit nonzero on any failed gate.
