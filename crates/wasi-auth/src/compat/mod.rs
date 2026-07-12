//! Private migration surface for the former DDD authentication crates.
//!
//! New applications must use the canonical modules. This namespace exists so
//! generated applications can migrate incrementally without publishing or
//! maintaining additional crates.

/// Imported DDD authentication implementation behind canonical re-exports.
#[cfg(feature = "ddd-cqrs")]
pub mod ddd_auth;
/// Former in-memory evaluator retained only for deterministic tests.
#[cfg(feature = "testkit-evaluator")]
pub mod ddd_authz;
