# Fuzzing

The pinned nightly and `cargo-fuzz` versions are recorded in
`compatibility.toml`. Run the bounded smoke suite with:

```bash
CARGO_FUZZ_BIN=/path/to/cargo-fuzz FUZZ_RUNS=10000 \
  bash scripts/run-fuzz-smoke.sh
```

The three targets cover:

- `authzen-json`: request/decision decoding, bounds, and semantic round trips;
- `attributes`: attribute names, values, provenance JSON, and collections; and
- `provider-response`: status/header/body handling through the public
  `AuthzenClient`, including fail-closed malformed responses.

Unknown standard AuthZEN members are valid forward-compatible input. Fuzz
failures must distinguish that from unknown `wasi_authz` members, which are
invalid. Only null, an empty array, or an empty object is an empty obligation;
non-empty values and malformed scalar obligations are unsupported.

The smoke run is a regression gate, not a substitute for sustained fuzzing.
Promotion requires reviewing crash artifacts and running longer corpus-backed
jobs outside the time-bounded pull-request lane.
