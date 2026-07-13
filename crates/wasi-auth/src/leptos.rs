//! Leptos request-context helpers for native trusted ingress.

use leptos::prelude::{provide_context, use_context};
use thiserror::Error;

use crate::context::{AuthenticationAssurance, VerifiedAuthContext, VerifiedRequestContext};

/// Leptos authentication context failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum LeptosAuthError {
    /// Trusted ingress did not install a verified request context.
    #[error("verified authentication context is missing")]
    MissingContext,
    /// The current session does not satisfy the required assurance.
    #[error("authentication assurance is insufficient")]
    InsufficientAssurance,
}

/// Installs a verified context into the current Leptos request owner.
///
/// Call this from `leptos_wasi::Handler::handle_with_context` after native
/// trusted ingress has authenticated the request.
pub fn provide_verified_auth_context(context: VerifiedAuthContext) {
    provide_context(context);
}

/// Installs identity and current authorization facts into a Leptos request.
pub fn provide_verified_request_context(context: VerifiedRequestContext) {
    provide_context(context.auth().clone());
    provide_context(context);
}

/// Returns identity and current authorization facts installed by ingress.
///
/// # Errors
///
/// Returns [`LeptosAuthError::MissingContext`] when dispatch bypassed ingress.
pub fn current_verified_request_context() -> Result<VerifiedRequestContext, LeptosAuthError> {
    use_context::<VerifiedRequestContext>().ok_or(LeptosAuthError::MissingContext)
}

/// Returns the current verified context.
///
/// # Errors
///
/// Returns [`LeptosAuthError::MissingContext`] when the route was not entered
/// through trusted ingress.
pub fn current_verified_auth_context() -> Result<VerifiedAuthContext, LeptosAuthError> {
    use_context::<VerifiedAuthContext>().ok_or(LeptosAuthError::MissingContext)
}

/// Requires a verified context at the requested assurance level.
///
/// # Errors
///
/// Returns [`LeptosAuthError`] when context is missing or assurance is too low.
pub fn require_assurance(
    required: AuthenticationAssurance,
) -> Result<VerifiedAuthContext, LeptosAuthError> {
    let context = current_verified_auth_context()?;
    if !context.assurance().satisfies(required) {
        return Err(LeptosAuthError::InsufficientAssurance);
    }
    Ok(context)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn missing_context_fails_closed() {
        assert_eq!(
            current_verified_auth_context(),
            Err(LeptosAuthError::MissingContext)
        );
    }
}
