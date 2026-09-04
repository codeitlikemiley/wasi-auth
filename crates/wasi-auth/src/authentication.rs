//! Account, credential, session, organization, and application-service contracts.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;
use std::marker::PhantomData;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::authorization::{
    AccessRequest, Authorizer, BatchAuthorizationError, Decision, DecisionProvider,
};
use crate::context::{
    AuthenticationAssurance, CredentialId, IdempotencyKey, InvitationId, OrganizationId, RoleId,
    SessionId, UserId,
};
use crate::mail::{EmailMessage, Mailer};

/// TOTP and single-use recovery-code primitives.
#[cfg(feature = "mfa")]
pub mod mfa;

mod error;

pub use error::{AuthError as WorkflowError, AuthErrorClass, AuthTransportMapping};

const MAX_TRANSACTION_ITEMS: usize = 1_024;

/// JWT and JWKS primitives used by the built-in authentication workflows.
#[cfg(feature = "jwt")]
#[allow(missing_docs)]
pub mod jwt;

/// WebAuthn/passkey primitives used by the runtime adapter.
#[cfg(feature = "passkeys")]
#[allow(missing_docs)]
pub mod passkeys {
    pub use passkey_auth::{
        Attachment, AuthSuccess, AuthenticationChallenge, AuthenticationResponse,
        AuthenticationState, Challenge, CredentialId, PasskeyCredential, RegistrationChallenge,
        RegistrationResponse, RegistrationState, Webauthn,
    };
}

/// Stable permission names used by the production template.
pub mod permissions {
    /// View organization details.
    pub const ORGANIZATION_VIEW: &str = "organization.view";
    /// Change organization settings.
    pub const ORGANIZATION_UPDATE: &str = "organization.update";
    /// View organization members.
    pub const MEMBER_VIEW: &str = "member.view";
    /// Invite organization members.
    pub const MEMBER_INVITE: &str = "member.invite";
    /// Change organization membership.
    pub const MEMBER_MANAGE: &str = "member.manage";
    /// View tenant roles.
    pub const ROLE_VIEW: &str = "role.view";
    /// Create or change tenant roles.
    pub const ROLE_MANAGE: &str = "role.manage";
    /// View tenant audit activity.
    pub const AUDIT_VIEW: &str = "audit.view";
    /// View the example counter.
    pub const COUNTER_VIEW: &str = "counter.view";
    /// Mutate the example counter.
    pub const COUNTER_CHANGE: &str = "counter.change";
    /// Reset the example counter.
    pub const COUNTER_RESET: &str = "counter.reset";
    /// View rendered dashboards.
    pub const DASHBOARD_VIEW: &str = "dashboard.view";
    /// Manage dashboard layout and published bindings.
    pub const DASHBOARD_MANAGE: &str = "dashboard.manage";
    /// View connection metadata.
    pub const RESOURCE_VIEW: &str = "resource.view";
    /// Create, update, or delete connections.
    pub const RESOURCE_MANAGE: &str = "resource.manage";
    /// View approved query definitions.
    pub const QUERY_VIEW: &str = "query.view";
    /// Create, approve, update, or delete queries.
    pub const QUERY_MANAGE: &str = "query.manage";
    /// Execute an approved read query.
    pub const QUERY_EXECUTE: &str = "query.execute";
    /// Execute a server-classified mutating query.
    pub const QUERY_EXECUTE_MUTATION: &str = "query.execute_mutation";
    /// View vault secret metadata.
    pub const VAULT_VIEW: &str = "vault.view";
    /// Create, bind, rotate, or delete vault secrets.
    pub const VAULT_MANAGE: &str = "vault.manage";
    /// Reveal vault secret material.
    pub const VAULT_REVEAL: &str = "vault.reveal";
    /// Transfer tenant ownership. Custom roles cannot receive this permission.
    pub const OWNERSHIP_TRANSFER: &str = "ownership.transfer";
    /// Manage global users. Tenant roles cannot receive this permission.
    pub const SYSTEM_USER_MANAGE: &str = "system.user.manage";
    /// Manage signing keys. Tenant roles cannot receive this permission.
    pub const SYSTEM_SIGNING_KEY_MANAGE: &str = "system.signing-key.manage";
    /// Publish policy bundles. Tenant roles cannot receive this permission.
    pub const SYSTEM_POLICY_MANAGE: &str = "system.policy.manage";
}

/// Domain validation or invariant failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum AuthenticationError {
    /// A required display name or email was invalid.
    #[error("authentication domain value is invalid")]
    InvalidValue,
    /// An operation targeted a disabled user.
    #[error("user is disabled")]
    UserDisabled,
    /// An operation would remove the final organization owner.
    #[error("organization must retain at least one owner")]
    LastOwner,
    /// A custom role attempted to grant an ownership or system permission.
    #[error("custom tenant role contains a restricted permission")]
    RestrictedPermission,
    /// A one-time invitation or credential operation has already completed.
    #[error("one-time operation has already completed")]
    AlreadyCompleted,
    /// A one-time operation has expired.
    #[error("one-time operation has expired")]
    Expired,
    /// A session has been revoked.
    #[error("session is revoked")]
    SessionRevoked,
}

/// Validated tenant permission.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Permission(String);

impl Permission {
    /// Validates a permission name.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::InvalidValue`] for a non-canonical name.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthenticationError> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 128
            || !value.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            })
        {
            return Err(AuthenticationError::InvalidValue);
        }
        Ok(Self(value))
    }

    /// Returns the permission name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }

    fn is_restricted_for_custom_role(&self) -> bool {
        matches!(
            self.as_str(),
            permissions::OWNERSHIP_TRANSFER
                | permissions::SYSTEM_USER_MANAGE
                | permissions::SYSTEM_SIGNING_KEY_MANAGE
                | permissions::SYSTEM_POLICY_MANAGE
        )
    }
}

/// Built-in organization role with fixed security semantics.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum BuiltInRole {
    /// Tenant owner with ownership-transfer authority.
    Owner,
    /// Tenant administrator without ownership-transfer authority.
    Admin,
    /// Normal tenant member.
    Member,
    /// Read-only tenant member.
    Viewer,
}

/// Tenant role and its permission set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Role {
    id: RoleId,
    name: String,
    built_in: Option<BuiltInRole>,
    permissions: BTreeSet<Permission>,
}

impl Role {
    /// Creates one built-in role and its fixed permission set.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError`] only if an internal permission constant
    /// violates the public permission contract.
    pub fn built_in(id: RoleId, role: BuiltInRole) -> Result<Self, AuthenticationError> {
        let names: &[&str] = match role {
            BuiltInRole::Owner => &[
                permissions::ORGANIZATION_VIEW,
                permissions::ORGANIZATION_UPDATE,
                permissions::MEMBER_VIEW,
                permissions::MEMBER_INVITE,
                permissions::MEMBER_MANAGE,
                permissions::ROLE_VIEW,
                permissions::ROLE_MANAGE,
                permissions::AUDIT_VIEW,
                permissions::COUNTER_VIEW,
                permissions::COUNTER_CHANGE,
                permissions::COUNTER_RESET,
                permissions::DASHBOARD_VIEW,
                permissions::DASHBOARD_MANAGE,
                permissions::RESOURCE_VIEW,
                permissions::RESOURCE_MANAGE,
                permissions::QUERY_VIEW,
                permissions::QUERY_MANAGE,
                permissions::QUERY_EXECUTE,
                permissions::QUERY_EXECUTE_MUTATION,
                permissions::VAULT_VIEW,
                permissions::VAULT_MANAGE,
                permissions::VAULT_REVEAL,
                permissions::OWNERSHIP_TRANSFER,
            ],
            BuiltInRole::Admin => &[
                permissions::ORGANIZATION_VIEW,
                permissions::ORGANIZATION_UPDATE,
                permissions::MEMBER_VIEW,
                permissions::MEMBER_INVITE,
                permissions::MEMBER_MANAGE,
                permissions::ROLE_VIEW,
                permissions::ROLE_MANAGE,
                permissions::AUDIT_VIEW,
                permissions::COUNTER_VIEW,
                permissions::COUNTER_CHANGE,
                permissions::COUNTER_RESET,
                permissions::DASHBOARD_VIEW,
                permissions::DASHBOARD_MANAGE,
                permissions::RESOURCE_VIEW,
                permissions::RESOURCE_MANAGE,
                permissions::QUERY_VIEW,
                permissions::QUERY_MANAGE,
                permissions::QUERY_EXECUTE,
                permissions::QUERY_EXECUTE_MUTATION,
                permissions::VAULT_VIEW,
                permissions::VAULT_MANAGE,
                permissions::VAULT_REVEAL,
            ],
            BuiltInRole::Member => &[
                permissions::ORGANIZATION_VIEW,
                permissions::MEMBER_VIEW,
                permissions::ROLE_VIEW,
                permissions::COUNTER_VIEW,
                permissions::COUNTER_CHANGE,
                permissions::DASHBOARD_VIEW,
                permissions::QUERY_VIEW,
                permissions::QUERY_EXECUTE,
            ],
            BuiltInRole::Viewer => &[
                permissions::ORGANIZATION_VIEW,
                permissions::MEMBER_VIEW,
                permissions::ROLE_VIEW,
                permissions::COUNTER_VIEW,
                permissions::DASHBOARD_VIEW,
            ],
        };
        let permissions = names
            .iter()
            .map(|name| Permission::new(*name))
            .collect::<Result<_, _>>()?;
        Ok(Self {
            id,
            name: format!("{role:?}").to_ascii_lowercase(),
            built_in: Some(role),
            permissions,
        })
    }

    /// Creates a custom tenant role.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError`] for an invalid name or restricted
    /// permission.
    pub fn custom(
        id: RoleId,
        name: impl Into<String>,
        permissions: impl IntoIterator<Item = Permission>,
    ) -> Result<Self, AuthenticationError> {
        let name = name.into();
        if name.trim() != name || name.is_empty() || name.len() > 100 {
            return Err(AuthenticationError::InvalidValue);
        }
        let permissions = permissions.into_iter().collect::<BTreeSet<_>>();
        if permissions
            .iter()
            .any(Permission::is_restricted_for_custom_role)
        {
            return Err(AuthenticationError::RestrictedPermission);
        }
        Ok(Self {
            id,
            name,
            built_in: None,
            permissions,
        })
    }

    /// Returns the role identifier.
    #[must_use]
    pub const fn id(&self) -> &RoleId {
        &self.id
    }

    /// Returns the role display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the built-in role classification, if any.
    #[must_use]
    pub const fn built_in_role(&self) -> Option<BuiltInRole> {
        self.built_in
    }

    /// Returns the role permission set.
    #[must_use]
    pub const fn permissions(&self) -> &BTreeSet<Permission> {
        &self.permissions
    }
}

/// Global account lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum UserStatus {
    /// Registration exists but primary email is not verified.
    PendingVerification,
    /// Account may access authorized application resources.
    Active,
    /// Account and every session are administratively disabled.
    Disabled,
    /// Personally identifying fields were redacted under an audited workflow.
    Anonymized,
}

/// Global user account. Organization membership is modeled separately.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct User {
    id: UserId,
    primary_email: String,
    status: UserStatus,
}

impl User {
    /// Creates a pending account.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::InvalidValue`] for an invalid email.
    pub fn register(
        id: UserId,
        primary_email: impl Into<String>,
    ) -> Result<Self, AuthenticationError> {
        let primary_email = primary_email.into();
        validate_email(&primary_email)?;
        Ok(Self {
            id,
            primary_email,
            status: UserStatus::PendingVerification,
        })
    }

    /// Marks the primary email verified.
    pub fn verify_email(&mut self) {
        if self.status == UserStatus::PendingVerification {
            self.status = UserStatus::Active;
        }
    }

    /// Disables the account. Session revocation is committed in the same unit
    /// of work by the application service.
    pub fn disable(&mut self) {
        self.status = UserStatus::Disabled;
    }

    /// Returns the user identifier.
    #[must_use]
    pub const fn id(&self) -> &UserId {
        &self.id
    }

    /// Returns the primary email.
    #[must_use]
    pub fn primary_email(&self) -> &str {
        &self.primary_email
    }

    /// Returns the lifecycle status.
    #[must_use]
    pub const fn status(&self) -> UserStatus {
        self.status
    }
}

/// Tenant organization lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum OrganizationStatus {
    /// Organization accepts authenticated traffic.
    Active,
    /// Organization is retained for audit but denies normal access.
    Archived,
}

/// Multi-tenant organization with an explicit non-empty owner set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Organization {
    id: OrganizationId,
    name: String,
    status: OrganizationStatus,
    owners: BTreeSet<UserId>,
}

impl Organization {
    /// Creates an active organization with its first owner.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::InvalidValue`] for an invalid name.
    pub fn create(
        id: OrganizationId,
        name: impl Into<String>,
        owner: UserId,
    ) -> Result<Self, AuthenticationError> {
        let name = name.into();
        if name.trim() != name || name.is_empty() || name.len() > 120 {
            return Err(AuthenticationError::InvalidValue);
        }
        Ok(Self {
            id,
            name,
            status: OrganizationStatus::Active,
            owners: BTreeSet::from([owner]),
        })
    }

    /// Adds another owner.
    pub fn add_owner(&mut self, user_id: UserId) {
        self.owners.insert(user_id);
    }

    /// Removes an owner while preserving the last-owner invariant.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::LastOwner`] when this would remove the
    /// final owner.
    pub fn remove_owner(&mut self, user_id: &UserId) -> Result<(), AuthenticationError> {
        if self.owners.contains(user_id) && self.owners.len() == 1 {
            return Err(AuthenticationError::LastOwner);
        }
        self.owners.remove(user_id);
        Ok(())
    }

    /// Returns the organization identifier.
    #[must_use]
    pub const fn id(&self) -> &OrganizationId {
        &self.id
    }

    /// Returns the organization display name.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Returns the lifecycle status.
    #[must_use]
    pub const fn status(&self) -> OrganizationStatus {
        self.status
    }

    /// Returns the current owner set.
    #[must_use]
    pub const fn owners(&self) -> &BTreeSet<UserId> {
        &self.owners
    }
}

/// Tenant membership lifecycle state.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum MembershipStatus {
    /// Membership grants role-derived access.
    Active,
    /// Membership is suspended and grants no access.
    Suspended,
    /// Membership was removed and grants no access.
    Removed,
}

/// User membership and assigned tenant roles.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Membership {
    organization_id: OrganizationId,
    user_id: UserId,
    role_ids: BTreeSet<RoleId>,
    status: MembershipStatus,
}

impl Membership {
    /// Creates an active membership with at least one role.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::InvalidValue`] when no role is supplied.
    pub fn new(
        organization_id: OrganizationId,
        user_id: UserId,
        role_ids: impl IntoIterator<Item = RoleId>,
    ) -> Result<Self, AuthenticationError> {
        let role_ids = role_ids.into_iter().collect::<BTreeSet<_>>();
        if role_ids.is_empty() {
            return Err(AuthenticationError::InvalidValue);
        }
        Ok(Self {
            organization_id,
            user_id,
            role_ids,
            status: MembershipStatus::Active,
        })
    }

    /// Returns the organization identifier.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Returns the member user identifier.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns assigned role identifiers.
    #[must_use]
    pub const fn role_ids(&self) -> &BTreeSet<RoleId> {
        &self.role_ids
    }

    /// Returns the membership status.
    #[must_use]
    pub const fn status(&self) -> MembershipStatus {
        self.status
    }
}

/// One-time invitation to an organization.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Invitation {
    id: InvitationId,
    organization_id: OrganizationId,
    email: String,
    role_ids: BTreeSet<RoleId>,
    expires_at_unix_seconds: u64,
    accepted_by: Option<UserId>,
    revoked: bool,
}

impl Invitation {
    /// Creates an invitation. The raw token is generated and stored separately.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError`] for an invalid email, empty role set, or
    /// already-expired lifetime.
    pub fn new(
        id: InvitationId,
        organization_id: OrganizationId,
        email: impl Into<String>,
        role_ids: impl IntoIterator<Item = RoleId>,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<Self, AuthenticationError> {
        let email = email.into();
        validate_email(&email)?;
        let role_ids = role_ids.into_iter().collect::<BTreeSet<_>>();
        if role_ids.is_empty() {
            return Err(AuthenticationError::InvalidValue);
        }
        if expires_at_unix_seconds <= now_unix_seconds {
            return Err(AuthenticationError::Expired);
        }
        Ok(Self {
            id,
            organization_id,
            email,
            role_ids,
            expires_at_unix_seconds,
            accepted_by: None,
            revoked: false,
        })
    }

    /// Accepts the invitation once.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError`] when expired, revoked, or already used.
    pub fn accept(
        &mut self,
        user_id: UserId,
        now_unix_seconds: u64,
    ) -> Result<(), AuthenticationError> {
        if self.revoked || self.accepted_by.is_some() {
            return Err(AuthenticationError::AlreadyCompleted);
        }
        if now_unix_seconds >= self.expires_at_unix_seconds {
            return Err(AuthenticationError::Expired);
        }
        self.accepted_by = Some(user_id);
        Ok(())
    }

    /// Returns the invitation identifier.
    #[must_use]
    pub const fn id(&self) -> &InvitationId {
        &self.id
    }

    /// Returns the invited organization.
    #[must_use]
    pub const fn organization_id(&self) -> &OrganizationId {
        &self.organization_id
    }

    /// Returns the normalized recipient email.
    #[must_use]
    pub fn email(&self) -> &str {
        &self.email
    }

    /// Returns assigned role identifiers.
    #[must_use]
    pub const fn role_ids(&self) -> &BTreeSet<RoleId> {
        &self.role_ids
    }
}

/// Active authenticated session metadata. Token hashes live in secret storage.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Session {
    id: SessionId,
    user_id: UserId,
    organization_id: Option<OrganizationId>,
    assurance: AuthenticationAssurance,
    expires_at_unix_seconds: u64,
    revoked_at_unix_seconds: Option<u64>,
}

impl Session {
    /// Creates an active bounded session.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::Expired`] for a non-future expiry.
    pub fn new(
        id: SessionId,
        user_id: UserId,
        organization_id: Option<OrganizationId>,
        assurance: AuthenticationAssurance,
        expires_at_unix_seconds: u64,
        now_unix_seconds: u64,
    ) -> Result<Self, AuthenticationError> {
        if expires_at_unix_seconds <= now_unix_seconds {
            return Err(AuthenticationError::Expired);
        }
        Ok(Self {
            id,
            user_id,
            organization_id,
            assurance,
            expires_at_unix_seconds,
            revoked_at_unix_seconds: None,
        })
    }

    /// Revokes the session idempotently.
    pub fn revoke(&mut self, now_unix_seconds: u64) {
        self.revoked_at_unix_seconds.get_or_insert(now_unix_seconds);
    }

    /// Returns whether the session may authenticate at the supplied time.
    #[must_use]
    pub fn is_active_at(&self, now_unix_seconds: u64) -> bool {
        self.revoked_at_unix_seconds.is_none() && now_unix_seconds < self.expires_at_unix_seconds
    }

    /// Returns the session identifier.
    #[must_use]
    pub const fn id(&self) -> &SessionId {
        &self.id
    }

    /// Returns the user identifier.
    #[must_use]
    pub const fn user_id(&self) -> &UserId {
        &self.user_id
    }

    /// Returns the selected organization.
    #[must_use]
    pub const fn organization_id(&self) -> Option<&OrganizationId> {
        self.organization_id.as_ref()
    }

    /// Returns the session assurance.
    #[must_use]
    pub const fn assurance(&self) -> AuthenticationAssurance {
        self.assurance
    }
}

/// Supported credential category.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum CredentialKind {
    /// Password hash credential.
    Password,
    /// OAuth provider identity and verifier state.
    OAuth,
    /// WebAuthn passkey credential.
    Passkey,
    /// Time-based one-time-password credential.
    Totp,
    /// One-way-hashed MFA recovery code.
    RecoveryCode,
}

impl CredentialKind {
    /// Returns the stable storage representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Password => "password",
            Self::OAuth => "oauth",
            Self::Passkey => "passkey",
            Self::Totp => "totp",
            Self::RecoveryCode => "recovery_code",
        }
    }
}

/// Non-secret credential lifecycle reference stored in the event log.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct CredentialDescriptor {
    /// Stable credential identifier.
    pub id: CredentialId,
    /// Owning user identifier.
    pub user_id: UserId,
    /// Password, OAuth, passkey, TOTP, or recovery-code type.
    pub kind: CredentialKind,
    /// Monotonic secret version.
    pub secret_version: u64,
}

/// Secret bytes that redact debug output and clear their allocation on drop.
pub struct SecretMaterial(Vec<u8>);

impl SecretMaterial {
    /// Wraps non-empty secret bytes.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::InvalidValue`] for empty material.
    pub fn new(bytes: impl Into<Vec<u8>>) -> Result<Self, AuthenticationError> {
        let bytes = bytes.into();
        if bytes.is_empty() {
            return Err(AuthenticationError::InvalidValue);
        }
        Ok(Self(bytes))
    }

    /// Returns the secret bytes to a storage or cryptographic adapter.
    #[must_use]
    pub fn expose(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Debug for SecretMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SecretMaterial([REDACTED])")
    }
}

impl Drop for SecretMaterial {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

/// Secret persistence independent from immutable domain events.
pub trait SecretStore: Sync {
    /// Store-specific failure.
    type Error: StdError + Send + Sync + 'static;

    /// Stores a versioned secret value.
    fn put<'a>(
        &'a self,
        credential: &'a CredentialDescriptor,
        material: &'a SecretMaterial,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'a;

    /// Removes all secret material for a credential.
    fn delete<'a>(
        &'a self,
        credential_id: &'a CredentialId,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send + 'a;
}

/// Sanitized event ready for the event store.
///
/// `payload_json` must contain lifecycle metadata only. Secret bytes are
/// represented exclusively by [`SecretMutation`].
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct SanitizedEvent {
    /// Aggregate category.
    pub aggregate_type: String,
    /// Aggregate identifier.
    pub aggregate_id: String,
    /// Optimistic revision expected before appending this event.
    pub expected_revision: u64,
    /// Stable event name.
    pub event_type: String,
    /// Sanitized serialized event payload.
    pub payload_json: String,
}

/// Supported durable authentication projection.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum ProjectionKind {
    /// Global user read model.
    User,
    /// Organization read model.
    Organization,
    /// Organization membership read model.
    Membership,
    /// Invitation read model.
    Invitation,
    /// Role and permission read model.
    Role,
    /// Session read model.
    Session,
    /// Authentication provider configuration.
    ProviderConfiguration,
    /// Redirect allowlist configuration.
    RedirectAllowlist,
    /// Signing-key metadata.
    SigningKey,
    /// Cedar policy bundle metadata.
    PolicyBundle,
}

impl ProjectionKind {
    /// Returns the stable storage representation.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Organization => "organization",
            Self::Membership => "membership",
            Self::Invitation => "invitation",
            Self::Role => "role",
            Self::Session => "session",
            Self::ProviderConfiguration => "provider_configuration",
            Self::RedirectAllowlist => "redirect_allowlist",
            Self::SigningKey => "signing_key",
            Self::PolicyBundle => "policy_bundle",
        }
    }
}

/// Read-model change committed with its source event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ProjectionMutation {
    /// Inserts or replaces one projection record.
    Upsert {
        /// Projection/table name selected by the storage adapter.
        projection: ProjectionKind,
        /// Stable record key.
        key: String,
        /// Sanitized serialized read-model value.
        value_json: String,
    },
    /// Deletes one projection record.
    Delete {
        /// Projection/table name selected by the storage adapter.
        projection: ProjectionKind,
        /// Stable record key.
        key: String,
    },
}

/// Secret-vault change committed in the same database transaction as events.
///
/// This type deliberately implements neither `Clone` nor serialization. Its
/// debug output never exposes secret material.
pub enum SecretMutation {
    /// Stores a new encrypted or one-way-hashed credential version.
    Put {
        /// Non-secret credential lifecycle descriptor.
        credential: CredentialDescriptor,
        /// Secret bytes passed directly to the vault adapter.
        material: SecretMaterial,
    },
    /// Deletes every stored version of a credential.
    Delete {
        /// Credential to remove.
        credential_id: CredentialId,
    },
}

impl fmt::Debug for SecretMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Put { credential, .. } => formatter
                .debug_struct("SecretMutation::Put")
                .field("credential", credential)
                .field("material", &"[REDACTED]")
                .finish(),
            Self::Delete { credential_id } => formatter
                .debug_struct("SecretMutation::Delete")
                .field("credential_id", credential_id)
                .finish(),
        }
    }
}

/// SpiceDB relationship operation queued transactionally with a domain change.
#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum RelationshipOperation {
    /// Makes a grant available after the relationship is confirmed.
    Grant,
    /// Denies access immediately and removes the relationship asynchronously.
    Revoke,
}

/// Provider-neutral durable relationship intent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct RelationshipOutboxIntent {
    /// Grant or revocation operation.
    pub operation: RelationshipOperation,
    /// Protected resource type and identifier, for example `document:123`.
    pub resource: String,
    /// Relationship/capability name.
    pub relation: String,
    /// Subject type and identifier, for example `user:456`.
    pub subject: String,
    /// Revision of the protected read model associated with this change.
    pub resource_revision: u64,
    /// Optional consistency token from the preceding provider operation.
    pub consistency_token: Option<String>,
}

impl RelationshipOutboxIntent {
    /// Returns whether local authorization must deny while this intent waits.
    #[must_use]
    pub const fn deny_while_pending(&self) -> bool {
        matches!(self.operation, RelationshipOperation::Revoke)
    }
}

/// Typed outbox intent committed with events and projections.
///
/// Mail bodies can contain one-time bearer values, so this type is not
/// serializable and uses the redacted [`EmailMessage`] debug implementation.
pub enum OutboxIntent {
    /// Transactional email delivery.
    Mail(EmailMessage),
    /// Optional external relationship synchronization.
    Relationship(RelationshipOutboxIntent),
}

impl fmt::Debug for OutboxIntent {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Mail(message) => formatter.debug_tuple("Mail").field(message).finish(),
            Self::Relationship(intent) => {
                formatter.debug_tuple("Relationship").field(intent).finish()
            }
        }
    }
}

/// Durable application mutation committed in one transaction.
///
/// All fields are private so callers cannot accidentally bypass construction
/// bounds. The mutation itself cannot be cloned or serialized because it may
/// contain secret and one-time mail material.
pub struct AuthMutation {
    idempotency_key: IdempotencyKey,
    operation: String,
    request_hash: [u8; 32],
    events: Vec<SanitizedEvent>,
    projections: Vec<ProjectionMutation>,
    secrets: Vec<SecretMutation>,
    outbox_intents: Vec<OutboxIntent>,
}

impl AuthMutation {
    /// Constructs one bounded atomic mutation.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationError::InvalidValue`] if no event is supplied
    /// or any mutation collection exceeds 1,024 entries.
    pub fn new(
        idempotency_key: IdempotencyKey,
        operation: impl Into<String>,
        request_hash: [u8; 32],
        events: Vec<SanitizedEvent>,
        projections: Vec<ProjectionMutation>,
        secrets: Vec<SecretMutation>,
        outbox_intents: Vec<OutboxIntent>,
    ) -> Result<Self, AuthenticationError> {
        let operation = operation.into();
        if operation.is_empty()
            || operation.len() > 128
            || !operation.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':')
            })
            || events.is_empty()
            || [
                events.len(),
                projections.len(),
                secrets.len(),
                outbox_intents.len(),
            ]
            .into_iter()
            .any(|length| length > MAX_TRANSACTION_ITEMS)
        {
            return Err(AuthenticationError::InvalidValue);
        }
        Ok(Self {
            idempotency_key,
            operation,
            request_hash,
            events,
            projections,
            secrets,
            outbox_intents,
        })
    }

    /// Returns the idempotency key.
    #[must_use]
    pub const fn idempotency_key(&self) -> &IdempotencyKey {
        &self.idempotency_key
    }

    /// Returns the stable application operation name.
    #[must_use]
    pub fn operation(&self) -> &str {
        &self.operation
    }

    /// Returns the canonical request fingerprint.
    ///
    /// Stores must reject reuse of an idempotency key with a different
    /// operation or fingerprint instead of replaying an unrelated result.
    #[must_use]
    pub const fn request_hash(&self) -> &[u8; 32] {
        &self.request_hash
    }

    /// Returns sanitized events in commit order.
    #[must_use]
    pub fn events(&self) -> &[SanitizedEvent] {
        &self.events
    }

    /// Returns read-model changes in commit order.
    #[must_use]
    pub fn projections(&self) -> &[ProjectionMutation] {
        &self.projections
    }

    /// Returns secret-vault changes in commit order.
    #[must_use]
    pub fn secrets(&self) -> &[SecretMutation] {
        &self.secrets
    }

    /// Returns durable outbox intents in commit order.
    #[must_use]
    pub fn outbox_intents(&self) -> &[OutboxIntent] {
        &self.outbox_intents
    }
}

impl fmt::Debug for AuthMutation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthMutation")
            .field("idempotency_key", &self.idempotency_key)
            .field("operation", &self.operation)
            .field("request_hash", &"[REDACTED]")
            .field("events", &self.events)
            .field("projections", &self.projections)
            .field("secrets", &self.secrets)
            .field("outbox_intents", &self.outbox_intents)
            .finish()
    }
}

/// Receipt returned after an atomic authentication mutation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CommitReceipt {
    /// Persisted aggregate revision.
    pub revision: u64,
    /// Whether an earlier idempotent result was replayed.
    pub replayed: bool,
}

/// Atomic event, projection, secret-reference, and outbox persistence port.
pub trait AuthUnitOfWork: Sync {
    /// Store-specific commit error.
    type Error: StdError + Send + Sync + 'static;

    /// Commits the complete mutation or rolls it back without partial effects.
    fn commit<'a>(
        &'a self,
        mutation: &'a AuthMutation,
    ) -> impl Future<Output = Result<CommitReceipt, Self::Error>> + Send + 'a;
}

/// Time source injected into authentication workflows.
pub trait Clock: Sync {
    /// Returns Unix time in seconds.
    fn now_unix_seconds(&self) -> u64;
}

/// Cryptographic randomness source injected into token workflows.
pub trait RandomSource: Sync {
    /// Randomness failure.
    type Error: StdError + Send + Sync + 'static;

    /// Fills the complete destination or returns an error.
    fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), Self::Error>;
}

/// Marker used by [`AuthApplicationBuilder`] for a missing dependency.
#[derive(Clone, Copy, Debug, Default)]
pub struct Missing;

/// Marker used by [`AuthApplicationBuilder`] for an installed dependency.
#[derive(Clone, Debug)]
pub struct Installed<T>(T);

/// Compile-time checked authentication application builder.
#[derive(Clone, Debug)]
pub struct AuthApplicationBuilder<S, A, M, V, C, R> {
    store: S,
    authorizer: A,
    mailer: M,
    secret_store: V,
    clock: C,
    randomness: R,
    marker: PhantomData<fn()>,
}

impl AuthApplicationBuilder<Missing, Missing, Missing, Missing, Missing, Missing> {
    /// Starts an empty builder. [`Self::build`] is unavailable until every
    /// required dependency has been installed.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            store: Missing,
            authorizer: Missing,
            mailer: Missing,
            secret_store: Missing,
            clock: Missing,
            randomness: Missing,
            marker: PhantomData,
        }
    }
}

impl Default for AuthApplicationBuilder<Missing, Missing, Missing, Missing, Missing, Missing> {
    fn default() -> Self {
        Self::new()
    }
}

impl<S, A, M, V, C, R> AuthApplicationBuilder<S, A, M, V, C, R> {
    /// Installs the atomic authentication unit of work.
    #[must_use]
    pub fn store<T>(self, store: T) -> AuthApplicationBuilder<Installed<T>, A, M, V, C, R> {
        AuthApplicationBuilder {
            store: Installed(store),
            authorizer: self.authorizer,
            mailer: self.mailer,
            secret_store: self.secret_store,
            clock: self.clock,
            randomness: self.randomness,
            marker: PhantomData,
        }
    }

    /// Installs the concrete static-dispatch authorizer.
    #[must_use]
    pub fn authorizer<T>(
        self,
        authorizer: T,
    ) -> AuthApplicationBuilder<S, Installed<T>, M, V, C, R> {
        AuthApplicationBuilder {
            store: self.store,
            authorizer: Installed(authorizer),
            mailer: self.mailer,
            secret_store: self.secret_store,
            clock: self.clock,
            randomness: self.randomness,
            marker: PhantomData,
        }
    }

    /// Installs the transactional mail provider.
    #[must_use]
    pub fn mailer<T>(self, mailer: T) -> AuthApplicationBuilder<S, A, Installed<T>, V, C, R> {
        AuthApplicationBuilder {
            store: self.store,
            authorizer: self.authorizer,
            mailer: Installed(mailer),
            secret_store: self.secret_store,
            clock: self.clock,
            randomness: self.randomness,
            marker: PhantomData,
        }
    }

    /// Installs encrypted or hashed secret persistence.
    #[must_use]
    pub fn secret_store<T>(
        self,
        secret_store: T,
    ) -> AuthApplicationBuilder<S, A, M, Installed<T>, C, R> {
        AuthApplicationBuilder {
            store: self.store,
            authorizer: self.authorizer,
            mailer: self.mailer,
            secret_store: Installed(secret_store),
            clock: self.clock,
            randomness: self.randomness,
            marker: PhantomData,
        }
    }

    /// Installs the time source.
    #[must_use]
    pub fn clock<T>(self, clock: T) -> AuthApplicationBuilder<S, A, M, V, Installed<T>, R> {
        AuthApplicationBuilder {
            store: self.store,
            authorizer: self.authorizer,
            mailer: self.mailer,
            secret_store: self.secret_store,
            clock: Installed(clock),
            randomness: self.randomness,
            marker: PhantomData,
        }
    }

    /// Installs the cryptographic randomness source.
    #[must_use]
    pub fn randomness<T>(
        self,
        randomness: T,
    ) -> AuthApplicationBuilder<S, A, M, V, C, Installed<T>> {
        AuthApplicationBuilder {
            store: self.store,
            authorizer: self.authorizer,
            mailer: self.mailer,
            secret_store: self.secret_store,
            clock: self.clock,
            randomness: Installed(randomness),
            marker: PhantomData,
        }
    }
}

impl<S, A, M, V, C, R>
    AuthApplicationBuilder<
        Installed<S>,
        Installed<A>,
        Installed<M>,
        Installed<V>,
        Installed<C>,
        Installed<R>,
    >
{
    /// Builds an application after every required dependency is present.
    #[must_use]
    pub fn build(self) -> AuthApplication<S, A, M, V, C, R> {
        AuthApplication {
            store: self.store.0,
            authorizer: self.authorizer.0,
            mailer: self.mailer.0,
            secret_store: self.secret_store.0,
            clock: self.clock.0,
            randomness: self.randomness.0,
        }
    }
}

/// Fully assembled authentication application with concrete dependencies.
#[derive(Clone, Debug)]
pub struct AuthApplication<S, A, M, V, C, R> {
    store: S,
    authorizer: A,
    mailer: M,
    secret_store: V,
    clock: C,
    randomness: R,
}

impl<S, A, M, V, C, R> AuthApplication<S, A, M, V, C, R> {
    /// Returns the atomic unit of work.
    #[must_use]
    pub const fn store(&self) -> &S {
        &self.store
    }

    /// Returns the concrete authorizer.
    #[must_use]
    pub const fn authorizer(&self) -> &A {
        &self.authorizer
    }

    /// Returns the concrete mailer.
    #[must_use]
    pub const fn mailer(&self) -> &M
    where
        M: Mailer,
    {
        &self.mailer
    }

    /// Returns secret persistence.
    #[must_use]
    pub const fn secret_store(&self) -> &V {
        &self.secret_store
    }

    /// Returns the application clock.
    #[must_use]
    pub const fn clock(&self) -> &C {
        &self.clock
    }

    /// Returns the randomness source.
    #[must_use]
    pub const fn randomness(&self) -> &R {
        &self.randomness
    }
}

impl<S, A, M, V, C, R> AuthApplication<S, A, M, V, C, R>
where
    S: AuthUnitOfWork,
{
    /// Commits one complete authentication mutation atomically.
    ///
    /// # Errors
    ///
    /// Returns the concrete storage failure without exposing partial success.
    pub async fn commit(&self, mutation: &AuthMutation) -> Result<CommitReceipt, S::Error> {
        self.store.commit(mutation).await
    }
}

impl<S, A, M, V, C, R> AuthApplication<S, A, M, V, C, R>
where
    A: DecisionProvider,
{
    /// Evaluates one authorization request using the configured provider.
    ///
    /// # Errors
    ///
    /// Returns the concrete provider failure; callers must fail closed.
    pub async fn authorize(&self, request: &AccessRequest) -> Result<Decision, A::Error> {
        Authorizer::new(&self.authorizer).check(request).await
    }

    /// Evaluates a bounded authorization batch using provider-native batching.
    ///
    /// # Errors
    ///
    /// Returns an oversized-batch or provider failure.
    pub async fn batch_authorize(
        &self,
        requests: &[AccessRequest],
    ) -> Result<Vec<Decision>, BatchAuthorizationError<A::Error>> {
        Authorizer::new(&self.authorizer)
            .batch_check(requests)
            .await
    }
}

fn validate_email(value: &str) -> Result<(), AuthenticationError> {
    if value.trim() != value
        || value.len() > 320
        || value.chars().any(char::is_control)
        || value.split_once('@').is_none_or(|(local, domain)| {
            local.is_empty() || domain.is_empty() || !domain.contains('.')
        })
    {
        return Err(AuthenticationError::InvalidValue);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn organization_rejects_removing_final_owner() {
        let owner = UserId::new("user-owner").expect("valid fixture");
        let mut organization = Organization::create(
            OrganizationId::new("organization-one").expect("valid fixture"),
            "Example Organization",
            owner.clone(),
        )
        .expect("valid fixture");

        let result = organization.remove_owner(&owner);

        assert_eq!(result, Err(AuthenticationError::LastOwner));
    }

    #[test]
    fn custom_role_rejects_ownership_permission() {
        let result = Role::custom(
            RoleId::new("role-custom").expect("valid fixture"),
            "Custom",
            [Permission::new(permissions::OWNERSHIP_TRANSFER).expect("valid fixture")],
        );

        assert_eq!(result, Err(AuthenticationError::RestrictedPermission));
    }

    #[test]
    fn secret_debug_output_is_redacted() {
        let secret = SecretMaterial::new(b"top-secret".to_vec()).expect("valid fixture");

        assert_eq!(format!("{secret:?}"), "SecretMaterial([REDACTED])");
    }
}
