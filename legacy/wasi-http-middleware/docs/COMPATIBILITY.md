# Tested compatibility

This is the exact compatibility matrix exercised for `0.2.0-alpha.3`. A pinned
test result is not automatically a production-support promise; see
[Support matrix](SUPPORT.md) for promotion status.

| Surface | Tested version | Result |
|---|---|---|
| Rust | 1.93.0 | Workspace MSRV and CI quality-gate toolchain |
| Rust compilation target | `wasm32-wasip2` | Emits components; this does not make the public HTTP ABI Preview 2 |
| `wasip3` crate | 0.7.0 | Final WASI 0.3 bindings and runtime helpers |
| `wit-bindgen` | 0.59.0 | Binding macro used by the component crates |
| Public HTTP WIT | `wasi:http@0.3.0` | Exact final asynchronous component ABI |
| Wasmtime | 46.0.1 | Passing behavioral reference host |
| Tagged Spin | 4.0.2 | Does not provide the final `wasi:http@0.3.0` resources required by these components |
| Spin main | `c34c584dbf77b3a3528ad0536aa9ce4761b9f772` (`4.1.0-pre0`) | Final terminal and outbound HTTP pass experimentally |
| Spin main, WAC-precomposed | same commit | Default build panics in its CPU-accounting hook; a no-default-features diagnostic build passes |
| Spin native middleware | `27451471b8ba0faeffa01c5a4ddd6daee9a9d526` | Still uses the March release-candidate middleware WIT and cannot compose these final-WIT components |
| `wasm-bindgen` | 0.2.126 | Used only by the tested sibling Leptos browser bridge; not a dependency or ABI of this server-component workspace |

## What the Spin result means

The pinned Spin main result proves that Spin's developing host can instantiate
a plain final-WASI terminal and provide final-WASI outbound HTTP. It does not
yet establish a deployable middleware stack:

- the commit is not a tagged Spin release;
- WAC-precomposed handlers panic with the ordinary default feature set;
- disabling default features is a diagnostic workaround, not a production
  runtime recommendation; and
- Spin's native trigger middleware still speaks a release-candidate WIT that
  is type-incompatible with final `wasi:http@0.3.0`.

The project therefore keeps independent profiles for tagged stable, main
terminal, main composition, and native middleware behavior. Do not collapse
their results into a single “Spin supported” flag.

```bash
# Expected incompatibility on tagged Spin 4.0.2.
SPIN_COMPAT_PROFILE=stable-final bash scripts/run-spin-e2e.sh

# Positive plain-terminal check on the exact main commit.
SPIN_BIN="$(bash scripts/bootstrap-spin-main.sh default)"
SPIN_COMPAT_PROFILE=main-terminal \
  SPIN_BIN="$SPIN_BIN" bash scripts/run-spin-e2e.sh

# Expected CPU-accounting failure on the ordinary main build.
SPIN_COMPAT_PROFILE=main-precomposed-default \
  SPIN_BIN="$SPIN_BIN" bash scripts/run-spin-e2e.sh

# Positive diagnostic composition check without default features.
SPIN_NO_CPU_BIN="$(bash scripts/bootstrap-spin-main.sh no-default-features)"
SPIN_COMPAT_PROFILE=main-precomposed-no-cpu \
  SPIN_BIN="$SPIN_NO_CPU_BIN" bash scripts/run-spin-e2e.sh

# Expected RC-versus-final WIT mismatch at the pinned middleware revision.
SPIN_COMPAT_PROFILE=native-middleware \
  SPIN_BIN=/path/to/spin-at-27451471 bash scripts/run-spin-e2e.sh
```

`compatibility.toml` is the machine-readable authority for these versions and
full revisions. Any change requires rebuilding components and rerunning the
contract, runtime, streaming, and performance gates before updating this page.
