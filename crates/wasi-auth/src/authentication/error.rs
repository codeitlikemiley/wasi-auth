//! Transport-neutral authentication workflow failures.

use std::error::Error;
use std::fmt::{Display, Formatter};

/// Public authentication workflow failure safe for transport mapping.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthError {
    /// A bounded caller-controlled value failed validation.
    Validation {
        /// Public validation explanation without secret material.
        message: String,
    },
    /// Registration targeted an existing account.
    AlreadyRegistered,
    /// The account is administratively disabled.
    UserDisabled,
    /// No matching account exists.
    UserNotRegistered,
    /// Identity-provider configuration or selection is invalid.
    InvalidProvider,
    /// A token is malformed, untrusted, or contextually invalid.
    InvalidToken,
    /// A token or session exceeded its accepted lifetime.
    SessionExpired,
    /// The referenced session was revoked.
    SessionRevoked,
    /// The authenticated principal lacks required authority.
    PermissionDenied,
}

/// Stable error class shared by HTTP, gRPC, and server functions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum AuthErrorClass {
    /// Invalid caller input.
    InvalidArgument,
    /// A unique resource already exists.
    AlreadyExists,
    /// A requested resource does not exist.
    NotFound,
    /// Authentication is absent or no longer valid.
    Unauthenticated,
    /// Authentication succeeded but authorization failed.
    PermissionDenied,
}

/// Transport-neutral status mapping for one authentication failure class.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuthTransportMapping {
    /// HTTP response status.
    pub http_status: u16,
    /// Canonical gRPC status name.
    pub grpc_code: &'static str,
    /// Stable server-function error code.
    pub server_fn_code: &'static str,
}

impl AuthError {
    /// Creates a public validation failure.
    #[must_use]
    pub fn validation(message: impl Into<String>) -> Self {
        Self::Validation {
            message: message.into(),
        }
    }

    /// Returns a stable machine-readable error code.
    #[must_use]
    pub fn public_code(&self) -> &'static str {
        match self {
            Self::Validation { .. } => "validation",
            Self::AlreadyRegistered => "already_registered",
            Self::UserDisabled => "user_disabled",
            Self::UserNotRegistered => "user_not_registered",
            Self::InvalidProvider => "invalid_provider",
            Self::InvalidToken => "invalid_token",
            Self::SessionExpired => "session_expired",
            Self::SessionRevoked => "session_revoked",
            Self::PermissionDenied => "permission_denied",
        }
    }

    /// Returns the redacted message safe to return to a caller.
    #[must_use]
    pub fn public_message(&self) -> String {
        match self {
            Self::Validation { message } => message.clone(),
            Self::AlreadyRegistered => "user is already registered".to_string(),
            Self::UserDisabled => "user is disabled".to_string(),
            Self::UserNotRegistered => "user is not registered".to_string(),
            Self::InvalidProvider => "auth provider is invalid".to_string(),
            Self::InvalidToken => "token is invalid".to_string(),
            Self::SessionExpired => "session is expired".to_string(),
            Self::SessionRevoked => "session is revoked".to_string(),
            Self::PermissionDenied => "permission denied".to_string(),
        }
    }

    /// Classifies the failure independently of transport.
    #[must_use]
    pub fn class(&self) -> AuthErrorClass {
        match self {
            Self::Validation { .. } | Self::InvalidProvider => AuthErrorClass::InvalidArgument,
            Self::AlreadyRegistered => AuthErrorClass::AlreadyExists,
            Self::UserNotRegistered => AuthErrorClass::NotFound,
            Self::InvalidToken | Self::SessionExpired | Self::SessionRevoked => {
                AuthErrorClass::Unauthenticated
            }
            Self::UserDisabled | Self::PermissionDenied => AuthErrorClass::PermissionDenied,
        }
    }

    /// Returns the HTTP, gRPC, and server-function mapping.
    #[must_use]
    pub fn transport_mapping(&self) -> AuthTransportMapping {
        self.class().transport_mapping()
    }
}

impl AuthErrorClass {
    /// Returns the transport mapping for this error class.
    #[must_use]
    pub fn transport_mapping(self) -> AuthTransportMapping {
        match self {
            Self::InvalidArgument => AuthTransportMapping {
                http_status: 400,
                grpc_code: "InvalidArgument",
                server_fn_code: "validation",
            },
            Self::AlreadyExists => AuthTransportMapping {
                http_status: 409,
                grpc_code: "AlreadyExists",
                server_fn_code: "conflict",
            },
            Self::NotFound => AuthTransportMapping {
                http_status: 404,
                grpc_code: "NotFound",
                server_fn_code: "not_found",
            },
            Self::Unauthenticated => AuthTransportMapping {
                http_status: 401,
                grpc_code: "Unauthenticated",
                server_fn_code: "auth_required",
            },
            Self::PermissionDenied => AuthTransportMapping {
                http_status: 403,
                grpc_code: "PermissionDenied",
                server_fn_code: "forbidden",
            },
        }
    }
}

impl Display for AuthError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Validation { message } => f.write_str(message),
            Self::AlreadyRegistered => f.write_str("user is already registered"),
            Self::UserDisabled => f.write_str("user is disabled"),
            Self::UserNotRegistered => f.write_str("user is not registered"),
            Self::InvalidProvider => f.write_str("auth provider is invalid"),
            Self::InvalidToken => f.write_str("token is invalid"),
            Self::SessionExpired => f.write_str("session is expired"),
            Self::SessionRevoked => f.write_str("session is revoked"),
            Self::PermissionDenied => f.write_str("permission denied"),
        }
    }
}

impl Error for AuthError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validation_maps_to_invalid_argument_transport_codes() {
        let error = AuthError::validation("email is required");

        assert_eq!(error.class(), AuthErrorClass::InvalidArgument);
        assert_eq!(error.transport_mapping().http_status, 400);
        assert_eq!(error.transport_mapping().grpc_code, "InvalidArgument");
    }

    #[test]
    fn already_registered_maps_to_conflict_transport_codes() {
        let mapping = AuthError::AlreadyRegistered.transport_mapping();

        assert_eq!(mapping.http_status, 409);
        assert_eq!(mapping.grpc_code, "AlreadyExists");
        assert_eq!(mapping.server_fn_code, "conflict");
    }

    #[test]
    fn invalid_token_maps_to_unauthenticated_transport_codes() {
        let mapping = AuthError::InvalidToken.transport_mapping();

        assert_eq!(mapping.http_status, 401);
        assert_eq!(mapping.grpc_code, "Unauthenticated");
        assert_eq!(mapping.server_fn_code, "auth_required");
    }

    #[test]
    fn permission_denied_maps_to_forbidden_transport_codes() {
        let mapping = AuthError::PermissionDenied.transport_mapping();

        assert_eq!(mapping.http_status, 403);
        assert_eq!(mapping.grpc_code, "PermissionDenied");
        assert_eq!(mapping.server_fn_code, "forbidden");
    }
}
