//! Validated identity and request context installed by trusted ingress.

use std::collections::BTreeSet;
use std::fmt::{self, Display, Formatter};

use serde::{Deserialize, Serialize};
use thiserror::Error;

const MAX_IDENTIFIER_BYTES: usize = 256;
const MAX_ISSUER_BYTES: usize = 512;

/// Failure produced while validating a bounded identifier or context.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum ContextError {
    /// A required identifier was empty.
    #[error("identifier must not be empty")]
    EmptyIdentifier,
    /// An identifier exceeded its bounded wire representation.
    #[error("identifier exceeds its maximum length")]
    IdentifierTooLong,
    /// An identifier contained whitespace or control characters.
    #[error("identifier contains unsupported characters")]
    InvalidIdentifier,
    /// The principal issuer was empty or invalid.
    #[error("principal issuer is invalid")]
    InvalidIssuer,
    /// The context expiry did not follow its issue time.
    #[error("authentication context lifetime is invalid")]
    InvalidLifetime,
}

macro_rules! bounded_identifier {
    ($(#[$meta:meta])* $name:ident) => {
        $(#[$meta])*
        #[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            /// Validates and constructs the identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ContextError`] when the value is empty, oversized, or
            /// contains whitespace or control characters.
            pub fn new(value: impl Into<String>) -> Result<Self, ContextError> {
                let value = value.into();
                validate_identifier(&value)?;
                Ok(Self(value))
            }

            /// Returns the validated identifier as a string slice.
            #[must_use]
            pub fn as_str(&self) -> &str {
                &self.0
            }

            /// Consumes the identifier and returns its string representation.
            #[must_use]
            pub fn into_string(self) -> String {
                self.0
            }
        }

        impl Display for $name {
            fn fmt(&self, formatter: &mut Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl TryFrom<String> for $name {
            type Error = ContextError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }
    };
}

bounded_identifier!(
    /// Stable global user identifier.
    UserId
);
bounded_identifier!(
    /// Stable tenant organization identifier.
    OrganizationId
);
bounded_identifier!(
    /// Stable authenticated session identifier.
    SessionId
);
bounded_identifier!(
    /// Request correlation identifier.
    RequestId
);
bounded_identifier!(
    /// Authorization decision identifier.
    DecisionId
);
bounded_identifier!(
    /// Activated policy revision identifier.
    PolicyRevision
);
bounded_identifier!(
    /// Credential reference whose secret material lives outside the event log.
    CredentialId
);
bounded_identifier!(
    /// Organization invitation identifier.
    InvitationId
);
bounded_identifier!(
    /// Tenant-scoped role identifier.
    RoleId
);
bounded_identifier!(
    /// Durable idempotency identifier for one application command.
    IdempotencyKey
);

/// Authentication assurance carried by a verified session.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[non_exhaustive]
pub enum AuthenticationAssurance {
    /// A primary credential was verified.
    Aal1,
    /// A second factor or phishing-resistant credential was verified.
    Aal2,
}

impl AuthenticationAssurance {
    /// Returns whether this assurance satisfies the required level.
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        self as u8 >= required as u8
    }
}

/// Authenticated user identity before request-boundary verification.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Principal {
    user_id: UserId,
    issuer: String,
    system_administrator: bool,
}

impl Principal {
    /// Constructs a principal issued by a validated identity provider.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the issuer is empty, oversized, or
    /// contains control characters.
    pub fn new(
        user_id: UserId,
        issuer: impl Into<String>,
        system_administrator: bool,
    ) -> Result<Self, ContextError> {
        let issuer = issuer.into();
        if issuer.is_empty()
            || issuer.len() > MAX_ISSUER_BYTES
            || issuer.chars().any(char::is_control)
        {
            return Err(ContextError::InvalidIssuer);
        }
        Ok(Self {
            user_id,
            issuer,
            system_administrator,
        })
    }

    /// Returns the global user identifier.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the validated identity issuer.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns whether this principal holds the out-of-band system role.
    #[must_use]
    pub const fn is_system_administrator(&self) -> bool {
        self.system_administrator
    }
}

/// Authenticated request context proven by a trusted boundary.
///
/// The type has no public constructor. Runtime adapters validate credentials,
/// deployment identity, audience, lifetime, and tenant selection before
/// installing it. Tests use [`crate::testkit::VerifiedAuthContextBuilder`].
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAuthContext {
    principal: Principal,
    organization_id: Option<OrganizationId>,
    session_id: SessionId,
    request_id: RequestId,
    assurance: AuthenticationAssurance,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    decision_id: Option<DecisionId>,
    policy_revision: Option<PolicyRevision>,
}

/// Current authorization facts loaded by trusted ingress.
///
/// The snapshot is assembled by a credential authenticator from authoritative
/// storage. Public transports cannot install it directly into a verified
/// request context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthorizationSnapshot {
    permissions: BTreeSet<String>,
    role_ids: BTreeSet<RoleId>,
    policy_revision: Option<PolicyRevision>,
    consistency_token: Option<String>,
}

impl AuthorizationSnapshot {
    /// Constructs a bounded snapshot from trusted storage values.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when a permission, role, policy revision, or
    /// consistency token violates the bounded identifier contract.
    pub fn new(
        permissions: impl IntoIterator<Item = impl Into<String>>,
        role_ids: impl IntoIterator<Item = RoleId>,
        policy_revision: Option<PolicyRevision>,
        consistency_token: Option<String>,
    ) -> Result<Self, ContextError> {
        let permissions = permissions
            .into_iter()
            .map(Into::into)
            .map(|permission| {
                validate_identifier(&permission)?;
                Ok(permission)
            })
            .collect::<Result<BTreeSet<_>, ContextError>>()?;
        if consistency_token.as_ref().is_some_and(|token| {
            token.is_empty() || token.len() > 4_096 || token.chars().any(char::is_control)
        }) {
            return Err(ContextError::InvalidIdentifier);
        }
        Ok(Self {
            permissions,
            role_ids: role_ids.into_iter().collect(),
            policy_revision,
            consistency_token,
        })
    }

    /// Returns whether the authoritative snapshot contains a permission.
    #[must_use]
    pub fn has_permission(&self, permission: &str) -> bool {
        self.permissions.contains(permission)
    }

    /// Returns the current permissions in deterministic order.
    pub fn permissions(&self) -> impl ExactSizeIterator<Item = &str> {
        self.permissions.iter().map(String::as_str)
    }

    /// Returns the current tenant role identifiers.
    pub fn role_ids(&self) -> impl ExactSizeIterator<Item = &RoleId> {
        self.role_ids.iter()
    }

    /// Returns the current policy revision, when one is available.
    #[must_use]
    pub const fn policy_revision(&self) -> Option<&PolicyRevision> {
        self.policy_revision.as_ref()
    }

    /// Returns the provider consistency token tied to these facts.
    #[must_use]
    pub fn consistency_token(&self) -> Option<&str> {
        self.consistency_token.as_deref()
    }
}

/// Identity and authorization facts proven together at trusted ingress.
///
/// The fields are private and the constructor is crate-private, preventing
/// application code from turning arbitrary headers into verified authority.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedRequestContext {
    auth: VerifiedAuthContext,
    authorization: AuthorizationSnapshot,
}

impl VerifiedRequestContext {
    pub(crate) const fn from_verified(
        auth: VerifiedAuthContext,
        authorization: AuthorizationSnapshot,
    ) -> Self {
        Self {
            auth,
            authorization,
        }
    }

    /// Returns the verified authentication context.
    #[must_use]
    pub const fn auth(&self) -> &VerifiedAuthContext {
        &self.auth
    }

    /// Returns current authorization facts loaded by trusted ingress.
    #[must_use]
    pub const fn authorization(&self) -> &AuthorizationSnapshot {
        &self.authorization
    }

    /// Splits the request context into its verified components.
    #[must_use]
    pub fn into_parts(self) -> (VerifiedAuthContext, AuthorizationSnapshot) {
        (self.auth, self.authorization)
    }
}

impl VerifiedAuthContext {
    #[cfg(any(test, feature = "http", feature = "testkit"))]
    pub(crate) fn from_validated(parts: ValidatedContextParts) -> Result<Self, ContextError> {
        if parts.expires_at_unix_seconds <= parts.issued_at_unix_seconds {
            return Err(ContextError::InvalidLifetime);
        }
        Ok(Self {
            principal: parts.principal,
            organization_id: parts.organization_id,
            session_id: parts.session_id,
            request_id: parts.request_id,
            assurance: parts.assurance,
            issued_at_unix_seconds: parts.issued_at_unix_seconds,
            expires_at_unix_seconds: parts.expires_at_unix_seconds,
            decision_id: parts.decision_id,
            policy_revision: parts.policy_revision,
        })
    }

    /// Returns the authenticated principal.
    #[must_use]
    pub const fn principal(&self) -> &Principal {
        &self.principal
    }

    /// Returns the selected tenant organization, when one was verified.
    #[must_use]
    pub const fn organization_id(&self) -> Option<&OrganizationId> {
        self.organization_id.as_ref()
    }

    /// Returns the authenticated session identifier.
    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    /// Returns the request correlation identifier.
    #[must_use]
    pub const fn request_id(&self) -> &RequestId {
        &self.request_id
    }

    /// Returns the established authentication assurance.
    #[must_use]
    pub const fn assurance(&self) -> AuthenticationAssurance {
        self.assurance
    }

    /// Returns the issue time as Unix seconds.
    #[must_use]
    pub const fn issued_at_unix_seconds(&self) -> u64 {
        self.issued_at_unix_seconds
    }

    /// Returns the expiry time as Unix seconds.
    #[must_use]
    pub const fn expires_at_unix_seconds(&self) -> u64 {
        self.expires_at_unix_seconds
    }

    /// Returns whether the context is expired at the supplied time.
    #[must_use]
    pub const fn is_expired_at(&self, now_unix_seconds: u64) -> bool {
        now_unix_seconds >= self.expires_at_unix_seconds
    }

    /// Returns the upstream authorization decision identifier, when present.
    #[must_use]
    pub const fn decision_id(&self) -> Option<&DecisionId> {
        self.decision_id.as_ref()
    }

    /// Returns the upstream policy revision, when present.
    #[must_use]
    pub const fn policy_revision(&self) -> Option<&PolicyRevision> {
        self.policy_revision.as_ref()
    }
}

#[cfg(any(test, feature = "http", feature = "testkit"))]
pub(crate) struct ValidatedContextParts {
    pub(crate) principal: Principal,
    pub(crate) organization_id: Option<OrganizationId>,
    pub(crate) session_id: SessionId,
    pub(crate) request_id: RequestId,
    pub(crate) assurance: AuthenticationAssurance,
    pub(crate) issued_at_unix_seconds: u64,
    pub(crate) expires_at_unix_seconds: u64,
    pub(crate) decision_id: Option<DecisionId>,
    pub(crate) policy_revision: Option<PolicyRevision>,
}

fn validate_identifier(value: &str) -> Result<(), ContextError> {
    if value.is_empty() {
        return Err(ContextError::EmptyIdentifier);
    }
    if value.len() > MAX_IDENTIFIER_BYTES {
        return Err(ContextError::IdentifierTooLong);
    }
    if value
        .chars()
        .any(|character| character.is_control() || character.is_whitespace() || character == '\0')
    {
        return Err(ContextError::InvalidIdentifier);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identifier_rejects_whitespace() {
        assert_eq!(
            UserId::new("user one"),
            Err(ContextError::InvalidIdentifier)
        );
    }

    #[test]
    fn assurance_aal2_satisfies_aal1() {
        assert!(AuthenticationAssurance::Aal2.satisfies(AuthenticationAssurance::Aal1));
    }
}
