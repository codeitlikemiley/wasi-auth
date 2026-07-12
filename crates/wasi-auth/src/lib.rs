//! Authentication, authorization, and trusted-ingress building blocks for WASI.
//!
//! The crate intentionally exposes a single feature-gated API. Production
//! applications can use [`authentication::AuthApplicationBuilder`] to assemble
//! concrete services with static dispatch, then install one
//! [`context::VerifiedAuthContext`] at the trusted request boundary.

#![deny(rustdoc::broken_intra_doc_links)]

pub mod authentication;
pub mod authorization;
#[cfg(feature = "cedar")]
pub mod cedar;
#[cfg(any(feature = "ddd-cqrs", feature = "testkit-evaluator"))]
#[allow(clippy::enum_variant_names, dead_code, missing_docs, unused_imports)]
mod compat;
#[cfg(feature = "http")]
pub mod config;
pub mod context;
#[cfg(feature = "ddd-cqrs")]
pub mod ddd;
#[cfg(feature = "http")]
pub mod http;
#[cfg(feature = "leptos")]
pub mod leptos;
pub mod mail;
#[cfg(feature = "postgres-kernel")]
pub mod postgres;
#[cfg(feature = "postgres-kernel")]
pub mod schema;
#[cfg(feature = "spicedb")]
pub mod spicedb;
#[cfg(feature = "spin-grpc")]
pub mod spin_grpc;
#[cfg(any(feature = "storage-postgres", feature = "storage-spin-sqlite"))]
pub mod storage;
#[cfg(any(test, feature = "testkit"))]
pub mod testkit;

pub use context::{
    AuthenticationAssurance, AuthorizationSnapshot, OrganizationId, Principal, RequestId,
    SessionId, UserId, VerifiedAuthContext, VerifiedRequestContext,
};
