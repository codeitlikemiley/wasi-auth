# Compatibility

| Surface | Status in `0.1.0-alpha.1` |
|---|---|
| AuthZEN Authorization API | Bounded access-evaluation profile |
| Decision obligations/advice | Rejected fail-closed |
| Decision caching | Unsupported |
| Native Rust | Supported |
| WASIp2 outbound HTTP | Additive feature |
| WASIp3 outbound HTTP | Additive feature |
| Cedar | Embedded provider |
| SpiceDB | CheckPermission adapter |
| Leptos | Typed request/server-function helpers |
| Non-HTTP triggers | Reuse contract/provider; trigger-specific PEP required |

The AuthZEN specification permits arbitrary properties and decision context.
This project intentionally accepts a smaller namespaced profile so unbounded
or unrecognized enforcement instructions cannot cross the trust boundary.
