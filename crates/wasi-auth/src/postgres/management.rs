//! Tenant management, invitations, system administration, and audit queries.

use std::error::Error as StdError;

#[cfg(feature = "password")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::Value;
#[cfg(feature = "password")]
use serde_json::json;
#[cfg(feature = "password")]
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
#[cfg(feature = "password")]
use zeroize::Zeroizing;

use super::organizations::OrganizationRecord;
#[cfg(feature = "password")]
use super::workflows::OutboxSealingKey;
use super::{PgRow, PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};

pub use super::access_model::{
    AccessModelError, ORGANIZATION_PERMISSION_CATALOG, OrganizationAccessModel, PermissionCatalog,
    PermissionDefinition, PermissionRisk,
};
#[cfg(feature = "password")]
use crate::mail::{EmailKind, TransactionalMailConfig, durable_transactional_mail_payload};
use crate::{
    authentication::{Clock, RandomSource},
    context::{RequestId, SessionId},
};

const GET_ORGANIZATION_SQL: &str = include_str!("get_organization.sql");
const UPDATE_ORGANIZATION_SQL: &str = include_str!("update_organization.sql");
const LIST_MEMBERSHIPS_SQL: &str = include_str!("list_memberships.sql");
const LIST_ROLES_SQL: &str = include_str!("list_roles.sql");
const UPSERT_ROLE_SQL: &str = include_str!("upsert_role.sql");
const DELETE_ROLE_SQL: &str = include_str!("delete_role.sql");
const ASSIGN_MEMBERSHIP_ROLE_SQL: &str = include_str!("assign_membership_role.sql");
const REMOVE_MEMBERSHIP_SQL: &str = include_str!("remove_membership.sql");
const LIST_INVITATIONS_SQL: &str = include_str!("list_invitations.sql");
#[cfg(feature = "password")]
const CREATE_INVITATION_SQL: &str = include_str!("create_invitation.sql");
#[cfg(feature = "password")]
const ACCEPT_INVITATION_SQL: &str = include_str!("accept_invitation.sql");
#[cfg(feature = "password")]
const REVOKE_INVITATION_SQL: &str = include_str!("revoke_invitation.sql");
#[cfg(feature = "password")]
const RESEND_INVITATION_SQL: &str = include_str!("resend_invitation.sql");
const LIST_ADMIN_USERS_SQL: &str = include_str!("list_admin_users.sql");
const SET_USER_DISABLED_SQL: &str = include_str!("set_user_disabled.sql");
const LIST_AUDIT_EVENTS_SQL: &str = include_str!("list_audit_events.sql");
const UUID_RANDOM_BYTES: usize = 10;
#[cfg(feature = "password")]
const TOKEN_BYTES: usize = 32;
#[cfg(feature = "password")]
const OUTBOX_NONCE_BYTES: usize = 12;
#[cfg(feature = "password")]
const INVITATION_TTL_MS: u64 = 7 * 24 * 60 * 60 * 1_000;

/// One organization membership.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MembershipRecord {
    /// Owning organization UUID.
    pub organization_id: String,
    /// Member user UUID.
    pub user_id: String,
    /// Member's primary display email.
    pub primary_email: String,
    /// Assigned role identifier.
    pub role_id: String,
    /// Membership lifecycle status.
    pub status: String,
    /// Join time in Unix milliseconds.
    pub joined_at_ms: u64,
}

/// One tenant role and its normalized permissions.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoleRecord {
    /// Owning organization UUID.
    pub organization_id: String,
    /// Stable role identifier.
    pub role_id: String,
    /// Human-readable role name.
    pub name: String,
    /// Whether product code owns this immutable role.
    pub built_in: bool,
    /// Sorted effective permissions.
    pub permissions: Vec<String>,
}

/// One invitation. The bearer token is intentionally absent.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct InvitationRecord {
    /// Invitation UUID.
    pub invitation_id: String,
    /// Destination organization UUID.
    pub organization_id: String,
    /// Normalized invited email.
    pub email: String,
    /// Role granted on acceptance.
    pub role_id: String,
    /// Invitation lifecycle status.
    pub status: String,
    /// Expiry in Unix milliseconds.
    pub expires_at_ms: u64,
}

/// One system-administration user row.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AdminUserRecord {
    /// User UUID.
    pub user_id: String,
    /// Primary display email.
    pub primary_email: String,
    /// Account lifecycle status.
    pub status: String,
    /// Creation time in Unix milliseconds.
    pub created_at_ms: u64,
}

/// Stable sequence-based audit event.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditEventRecord {
    /// Monotonic database cursor.
    pub sequence: u64,
    /// Optional tenant organization UUID.
    pub organization_id: Option<String>,
    /// Actor user UUID or `system`.
    pub actor_user_id: String,
    /// Stable action name.
    pub action: String,
    /// Protected resource category.
    pub resource_type: String,
    /// Protected resource identifier.
    pub resource_id: String,
    /// Stable operation outcome.
    pub outcome: String,
    /// Recording time in Unix milliseconds.
    pub occurred_at_ms: u64,
}

/// Bounded audit page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuditPage {
    /// Ordered events after the requested cursor.
    pub events: Vec<AuditEventRecord>,
    /// Cursor of the final returned event or the input cursor.
    pub next_cursor: u64,
}

/// Custom-role mutation input.
#[derive(Clone, Debug)]
pub struct UpsertRoleRequest {
    /// Verified actor session.
    pub session_id: SessionId,
    /// Target organization UUID.
    pub organization_id: String,
    /// Stable custom role identifier.
    pub role_id: String,
    /// Human-readable role name.
    pub name: String,
    /// Requested permissions from the tenant catalog.
    pub permissions: Vec<String>,
    /// Request correlation identifier.
    pub request_id: RequestId,
}

/// Core organization management service.
pub struct OrganizationManagementService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
}

impl<T, C, R> OrganizationManagementService<T, C, R> {
    /// Assembles the management service from runtime dependencies.
    #[must_use]
    pub const fn new(store: PostgresAuthStore<T>, clock: C, randomness: R) -> Self {
        Self {
            store,
            clock,
            randomness,
        }
    }
}

impl<T, C, R> OrganizationManagementService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Loads one organization through the actor's active membership.
    ///
    /// # Errors
    ///
    /// Returns validation, authorization, row, or transport failures.
    pub async fn organization(
        &self,
        session_id: &SessionId,
        organization_id: &str,
    ) -> Result<OrganizationRecord, ManagementError<T::Error>> {
        let organization_id = parse_uuid(organization_id)?;
        let rows = self
            .query(
                GET_ORGANIZATION_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    now_value(&self.clock),
                ],
            )
            .await?;
        rows.first()
            .map(decode_organization)
            .transpose()?
            .ok_or(ManagementError::NotAuthorized)
    }

    /// Updates an organization name under AAL2 and `organization.update`.
    ///
    /// # Errors
    ///
    /// Returns validation, authorization, randomness, row, or transport failures.
    pub async fn update_organization(
        &self,
        session_id: &SessionId,
        organization_id: &str,
        name: &str,
        request_id: &RequestId,
    ) -> Result<OrganizationRecord, ManagementError<T::Error>> {
        let organization_id = parse_uuid(organization_id)?;
        let name = bounded_name(name, 120)?;
        let now_ms = now_ms(&self.clock);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .query(
                UPDATE_ORGANIZATION_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    text(name),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        rows.first()
            .map(decode_organization)
            .transpose()?
            .ok_or(ManagementError::NotAuthorized)
    }

    /// Lists memberships under `member.view`.
    ///
    /// # Errors
    ///
    /// Returns validation, authorization, row, or transport failures.
    pub async fn list_memberships(
        &self,
        session_id: &SessionId,
        organization_id: &str,
    ) -> Result<Vec<MembershipRecord>, ManagementError<T::Error>> {
        let organization_id = parse_uuid(organization_id)?;
        let rows = self
            .query(
                LIST_MEMBERSHIPS_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    now_value(&self.clock),
                ],
            )
            .await?;
        if rows.is_empty() {
            return Err(ManagementError::NotAuthorized);
        }
        rows.iter().map(decode_membership).collect()
    }

    /// Lists tenant roles under `role.view`.
    ///
    /// # Errors
    ///
    /// Returns validation, authorization, row, or transport failures.
    pub async fn list_roles(
        &self,
        session_id: &SessionId,
        organization_id: &str,
    ) -> Result<Vec<RoleRecord>, ManagementError<T::Error>> {
        let organization_id = parse_uuid(organization_id)?;
        let rows = self
            .query(
                LIST_ROLES_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    now_value(&self.clock),
                ],
            )
            .await?;
        if rows.is_empty() {
            return Err(ManagementError::NotAuthorized);
        }
        rows.iter().map(decode_role).collect()
    }

    /// Creates or replaces a custom role under AAL2 and `role.manage`.
    ///
    /// # Errors
    ///
    /// Rejects built-ins/restricted permissions and propagates persistence failures.
    pub async fn upsert_role(
        &self,
        mut request: UpsertRoleRequest,
    ) -> Result<RoleRecord, ManagementError<T::Error>> {
        let organization_id = parse_uuid(&request.organization_id)?;
        validate_role_id(&request.role_id, false)?;
        let name = bounded_name(&request.name, 80)?;
        if request.permissions.len() > 100 {
            return Err(ManagementError::InvalidRequest);
        }
        request.permissions.sort();
        request.permissions.dedup();
        // Auto-expand transitive dependencies for custom-role UX, then reject
        // unknown and non-eligible permissions (including ownership.transfer).
        let access_model = OrganizationAccessModel::product_default();
        request.permissions = access_model
            .expand_with_dependencies(&request.permissions)
            .map_err(map_access_model_error)?;
        access_model
            .validate_custom_role_permissions(&request.permissions)
            .map_err(map_access_model_error)?;
        let permissions = serde_json::to_value(&request.permissions)
            .map_err(|_| ManagementError::InvalidRequest)?;
        let now_ms = now_ms(&self.clock);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .query(
                UPSERT_ROLE_SQL,
                vec![
                    text(request.session_id.as_str()),
                    text(organization_id),
                    text(request.role_id),
                    text(name),
                    PgValue::Json(permissions),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request.request_id.as_str()),
                ],
            )
            .await?;
        rows.first()
            .map(decode_role)
            .transpose()?
            .ok_or(ManagementError::NotAuthorized)
    }

    /// Deletes a custom role under AAL2 and `role.manage`.
    ///
    /// Built-in roles cannot be deleted. Active memberships or pending invitations
    /// that still use the role fail with [`ManagementError::RoleInUse`]. Residual
    /// non-active memberships and non-pending invitations are re-pointed to the
    /// built-in `member` role so foreign keys allow removal. Successful deletes
    /// bump `authorization_revision` and write an audit event.
    ///
    /// # Errors
    ///
    /// Returns validation, authorization, conflict, row, or transport failures.
    pub async fn delete_role(
        &self,
        session_id: &SessionId,
        organization_id: &str,
        role_id: &str,
        request_id: &RequestId,
    ) -> Result<(), ManagementError<T::Error>> {
        let organization_id = parse_uuid(organization_id)?;
        validate_role_id(role_id, false)?;
        let now_ms = now_ms(&self.clock);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .query(
                DELETE_ROLE_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    text(role_id),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        let Some(row) = rows.first() else {
            return Err(ManagementError::NotAuthorized);
        };
        match row.required_text("outcome")? {
            "deleted" => Ok(()),
            "in_use" => {
                let member_count = to_u64(row.required_i64("member_count")?)?;
                let invitation_count = to_u64(row.required_i64("invitation_count")?)?;
                Err(ManagementError::RoleInUse {
                    member_count,
                    invitation_count,
                })
            }
            _ => Err(ManagementError::InvalidRow),
        }
    }

    /// Assigns a role while serializing ownership transitions.
    ///
    /// # Errors
    ///
    /// Rejects unauthorized changes and final-owner violations.
    pub async fn assign_role(
        &self,
        session_id: &SessionId,
        organization_id: &str,
        user_id: &str,
        role_id: &str,
        request_id: &RequestId,
    ) -> Result<MembershipRecord, ManagementError<T::Error>> {
        let organization_id = parse_uuid(organization_id)?;
        let user_id = parse_uuid(user_id)?;
        validate_role_id(role_id, true)?;
        let now_ms = now_ms(&self.clock);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .query(
                ASSIGN_MEMBERSHIP_ROLE_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    text(user_id),
                    text(role_id),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        rows.first()
            .map(decode_membership)
            .transpose()?
            .ok_or(ManagementError::ProtectedInvariant)
    }

    /// Removes a membership while preserving at least one owner.
    ///
    /// # Errors
    ///
    /// Rejects unauthorized changes and final-owner violations.
    pub async fn remove_member(
        &self,
        session_id: &SessionId,
        organization_id: &str,
        user_id: &str,
        request_id: &RequestId,
    ) -> Result<(), ManagementError<T::Error>> {
        let organization_id = parse_uuid(organization_id)?;
        let user_id = parse_uuid(user_id)?;
        let now_ms = now_ms(&self.clock);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .query(
                REMOVE_MEMBERSHIP_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    text(user_id),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        if rows
            .first()
            .and_then(|row| row.required_text("outcome").ok())
            == Some("removed")
        {
            Ok(())
        } else {
            Err(ManagementError::ProtectedInvariant)
        }
    }

    /// Lists organization invitations under `member.view`.
    ///
    /// # Errors
    ///
    /// Returns validation, authorization, row, or transport failures.
    pub async fn list_invitations(
        &self,
        session_id: &SessionId,
        organization_id: &str,
    ) -> Result<Vec<InvitationRecord>, ManagementError<T::Error>> {
        let organization_id = parse_uuid(organization_id)?;
        let rows = self
            .query(
                LIST_INVITATIONS_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    now_value(&self.clock),
                ],
            )
            .await?;
        if rows
            .first()
            .and_then(|row| row.bool("authorized").ok())
            .flatten()
            != Some(true)
        {
            return Err(ManagementError::NotAuthorized);
        }
        rows.iter()
            .filter(|row| row.text("invitation_id").ok().flatten().is_some())
            .map(decode_invitation)
            .collect()
    }

    /// Lists users for an AAL2 system administrator.
    ///
    /// # Errors
    ///
    /// Returns authorization, row, or transport failures.
    pub async fn list_admin_users(
        &self,
        session_id: &SessionId,
    ) -> Result<Vec<AdminUserRecord>, ManagementError<T::Error>> {
        let rows = self
            .query(
                LIST_ADMIN_USERS_SQL,
                vec![text(session_id.as_str()), now_value(&self.clock)],
            )
            .await?;
        if rows.is_empty() {
            return Err(ManagementError::NotAuthorized);
        }
        rows.iter().map(decode_admin_user).collect()
    }

    /// Disables or restores a user while preserving every organization's owner invariant.
    ///
    /// # Errors
    ///
    /// Rejects unauthorized/final-owner changes and persistence failures.
    pub async fn set_user_disabled(
        &self,
        session_id: &SessionId,
        user_id: &str,
        disabled: bool,
        request_id: &RequestId,
    ) -> Result<AdminUserRecord, ManagementError<T::Error>> {
        let user_id = parse_uuid(user_id)?;
        let now_ms = now_ms(&self.clock);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .query(
                SET_USER_DISABLED_SQL,
                vec![
                    text(session_id.as_str()),
                    text(user_id),
                    PgValue::Bool(disabled),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        rows.first()
            .map(decode_admin_user)
            .transpose()?
            .ok_or(ManagementError::ProtectedInvariant)
    }

    /// Reads a bounded sequence-based audit page.
    ///
    /// # Errors
    ///
    /// Returns validation, authorization, row, or transport failures.
    pub async fn list_audit_events(
        &self,
        session_id: &SessionId,
        organization_id: Option<&str>,
        after_cursor: u64,
        limit: usize,
    ) -> Result<AuditPage, ManagementError<T::Error>> {
        if limit == 0 || limit > 100 {
            return Err(ManagementError::InvalidRequest);
        }
        let organization = organization_id.map(parse_uuid).transpose()?;
        let rows = self
            .query(
                LIST_AUDIT_EVENTS_SQL,
                vec![
                    text(session_id.as_str()),
                    organization.map_or(PgValue::Null, text),
                    i64_value(after_cursor),
                    PgValue::I64(i64::try_from(limit).unwrap_or(i64::MAX)),
                    now_value(&self.clock),
                ],
            )
            .await?;
        if rows
            .first()
            .and_then(|row| row.bool("authorized").ok())
            .flatten()
            != Some(true)
        {
            return Err(ManagementError::NotAuthorized);
        }
        let events = rows
            .iter()
            .filter(|row| row.i64("sequence").ok().flatten().is_some())
            .map(decode_audit)
            .collect::<Result<Vec<_>, _>>()?;
        let next_cursor = events.last().map_or(after_cursor, |event| event.sequence);
        Ok(AuditPage {
            events,
            next_cursor,
        })
    }

    async fn query(
        &self,
        sql: &'static str,
        values: Vec<PgValue>,
    ) -> Result<Vec<PgRow>, ManagementError<T::Error>> {
        self.store
            .transport()
            .query(sql, values)
            .await
            .map_err(map_transport_error::<T>)
    }

    fn uuid(&self, now_ms: u64) -> Result<Uuid, ManagementError<T::Error>> {
        uuid_v7(now_ms, &self.randomness).map_err(|_| ManagementError::RandomnessUnavailable)
    }
}

/// Invitation creation and acceptance with opaque tokens and durable mail.
#[cfg(feature = "password")]
pub struct InvitationService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
    outbox_key: OutboxSealingKey,
    transactional_mail_config: Option<TransactionalMailConfig>,
}

#[cfg(feature = "password")]
impl<T, C, R> InvitationService<T, C, R> {
    /// Assembles the invitation service from runtime dependencies.
    #[must_use]
    pub const fn new(
        store: PostgresAuthStore<T>,
        clock: C,
        randomness: R,
        outbox_key: OutboxSealingKey,
    ) -> Self {
        Self {
            store,
            clock,
            randomness,
            outbox_key,
            transactional_mail_config: None,
        }
    }

    /// Enables enqueue-time rendering with startup-validated mail settings.
    #[must_use]
    pub fn with_transactional_mail_config(mut self, config: TransactionalMailConfig) -> Self {
        self.transactional_mail_config = Some(config);
        self
    }
}

#[cfg(feature = "password")]
impl<T, C, R> InvitationService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Creates an invitation and encrypted mail intent atomically.
    ///
    /// # Errors
    ///
    /// Returns validation, authorization, crypto, randomness, row, or transport failures.
    pub async fn create(
        &self,
        session_id: &SessionId,
        organization_id: &str,
        email: &str,
        role_id: &str,
        request_id: &RequestId,
    ) -> Result<InvitationRecord, ManagementError<T::Error>> {
        let organization_id = parse_uuid(organization_id)?;
        let email = normalize_email(email)?;
        validate_role_id(role_id, true)?;
        let now_ms = now_ms(&self.clock);
        let invitation_id = self.uuid(now_ms)?;
        let outbox_id = self.uuid(now_ms)?;
        let audit_id = self.uuid(now_ms)?;
        let mut raw = [0_u8; TOKEN_BYTES];
        let mut nonce = [0_u8; OUTBOX_NONCE_BYTES];
        self.randomness
            .fill_bytes(&mut raw)
            .map_err(|_| ManagementError::RandomnessUnavailable)?;
        self.randomness
            .fill_bytes(&mut nonce)
            .map_err(|_| ManagementError::RandomnessUnavailable)?;
        let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(raw));
        let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let payload = if let Some(config) = &self.transactional_mail_config {
            durable_transactional_mail_payload(
                config,
                EmailKind::Invitation,
                &email,
                token.as_str(),
            )
            .map_err(|_| ManagementError::InvalidRequest)?
        } else {
            serde_json::to_vec(&json!({
                "version": 1, "kind": "invitation", "recipient": email,
                "token": token.as_str(), "redirect_uri": "/organizations",
            }))
            .map_err(|_| ManagementError::Crypto)?
        };
        let sealed = self
            .outbox_key
            .seal(nonce, &payload)
            .map_err(|_| ManagementError::Crypto)?;
        let rows = self
            .store
            .transport()
            .query(
                CREATE_INVITATION_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    text(email),
                    text(role_id),
                    text(invitation_id),
                    PgValue::Bytes(token_hash.to_vec()),
                    i64_value(now_ms.saturating_add(INVITATION_TTL_MS)),
                    text(outbox_id),
                    text(format!("invitation:{invitation_id}")),
                    text(sealed.key_version),
                    PgValue::Bytes(sealed.ciphertext),
                    text(audit_id),
                    text(request_id.as_str()),
                    i64_value(now_ms),
                ],
            )
            .await
            .map_err(map_transport_error::<T>)?;
        rows.first()
            .map(decode_invitation)
            .transpose()?
            .ok_or(ManagementError::NotAuthorized)
    }

    /// Consumes an invitation for the verified session email.
    ///
    /// # Errors
    ///
    /// Returns invalid-token, assurance, row, or transport failures.
    pub async fn accept(
        &self,
        session_id: &SessionId,
        token: &str,
        request_id: &RequestId,
    ) -> Result<OrganizationRecord, ManagementError<T::Error>> {
        if token.len() < 32 || token.len() > 512 || token.chars().any(char::is_control) {
            return Err(ManagementError::InvalidRequest);
        }
        let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let now_ms = now_ms(&self.clock);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .store
            .transport()
            .query(
                ACCEPT_INVITATION_SQL,
                vec![
                    text(session_id.as_str()),
                    PgValue::Bytes(token_hash.to_vec()),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await
            .map_err(map_transport_error::<T>)?;
        rows.first()
            .map(decode_organization)
            .transpose()?
            .ok_or(ManagementError::InvalidToken)
    }

    /// Revokes a pending invitation and consumes its one-time token.
    ///
    /// Requires AAL2+ and `member.invite`. Only `pending` invitations transition
    /// to `revoked`.
    ///
    /// # Errors
    ///
    /// Returns validation, authorization, randomness, row, or transport failures.
    pub async fn revoke(
        &self,
        session_id: &SessionId,
        organization_id: &str,
        invitation_id: &str,
        request_id: &RequestId,
    ) -> Result<InvitationRecord, ManagementError<T::Error>> {
        let organization_id = parse_uuid(organization_id)?;
        let invitation_id = parse_uuid(invitation_id)?;
        let now_ms = now_ms(&self.clock);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .store
            .transport()
            .query(
                REVOKE_INVITATION_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    text(invitation_id),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await
            .map_err(map_transport_error::<T>)?;
        rows.first()
            .map(decode_invitation)
            .transpose()?
            .ok_or(ManagementError::NotAuthorized)
    }

    /// Resends a pending invitation with a rotated token and extended TTL.
    ///
    /// Requires AAL2+ and `member.invite`. Prior one-time tokens are consumed so
    /// the previous mail link stops working. Mutation SQL is one statement; a
    /// short preflight only loads the recipient email for outbox sealing.
    ///
    /// # Errors
    ///
    /// Returns validation, authorization, crypto, randomness, row, or transport failures.
    pub async fn resend(
        &self,
        session_id: &SessionId,
        organization_id: &str,
        invitation_id: &str,
        request_id: &RequestId,
    ) -> Result<InvitationRecord, ManagementError<T::Error>> {
        let organization_id = parse_uuid(organization_id)?;
        let invitation_id = parse_uuid(invitation_id)?;
        let email = self
            .pending_invitation_email(session_id, &organization_id, &invitation_id)
            .await?;
        let now_ms = now_ms(&self.clock);
        let outbox_id = self.uuid(now_ms)?;
        let audit_id = self.uuid(now_ms)?;
        let mut raw = [0_u8; TOKEN_BYTES];
        let mut nonce = [0_u8; OUTBOX_NONCE_BYTES];
        self.randomness
            .fill_bytes(&mut raw)
            .map_err(|_| ManagementError::RandomnessUnavailable)?;
        self.randomness
            .fill_bytes(&mut nonce)
            .map_err(|_| ManagementError::RandomnessUnavailable)?;
        let token = Zeroizing::new(URL_SAFE_NO_PAD.encode(raw));
        let token_hash: [u8; 32] = Sha256::digest(token.as_bytes()).into();
        let payload = if let Some(config) = &self.transactional_mail_config {
            durable_transactional_mail_payload(
                config,
                EmailKind::Invitation,
                &email,
                token.as_str(),
            )
            .map_err(|_| ManagementError::InvalidRequest)?
        } else {
            serde_json::to_vec(&json!({
                "version": 1, "kind": "invitation", "recipient": email,
                "token": token.as_str(), "redirect_uri": "/organizations",
            }))
            .map_err(|_| ManagementError::Crypto)?
        };
        let sealed = self
            .outbox_key
            .seal(nonce, &payload)
            .map_err(|_| ManagementError::Crypto)?;
        let rows = self
            .store
            .transport()
            .query(
                RESEND_INVITATION_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    text(invitation_id),
                    PgValue::Bytes(token_hash.to_vec()),
                    i64_value(now_ms.saturating_add(INVITATION_TTL_MS)),
                    text(outbox_id),
                    text(format!("invitation-resend:{outbox_id}")),
                    text(sealed.key_version),
                    PgValue::Bytes(sealed.ciphertext),
                    text(audit_id),
                    text(request_id.as_str()),
                    i64_value(now_ms),
                ],
            )
            .await
            .map_err(map_transport_error::<T>)?;
        rows.first()
            .map(decode_invitation)
            .transpose()?
            .ok_or(ManagementError::NotAuthorized)
    }

    /// Loads the recipient email for a pending invitation under `member.view`.
    ///
    /// Authorization for the subsequent mutation is re-checked in the write SQL.
    async fn pending_invitation_email(
        &self,
        session_id: &SessionId,
        organization_id: &str,
        invitation_id: &str,
    ) -> Result<String, ManagementError<T::Error>> {
        let invitations = self
            .store
            .transport()
            .query(
                LIST_INVITATIONS_SQL,
                vec![
                    text(session_id.as_str()),
                    text(organization_id),
                    now_value(&self.clock),
                ],
            )
            .await
            .map_err(map_transport_error::<T>)?;
        if invitations
            .first()
            .and_then(|row| row.bool("authorized").ok())
            .flatten()
            != Some(true)
        {
            return Err(ManagementError::NotAuthorized);
        }
        invitations
            .iter()
            .filter_map(|row| decode_invitation::<T::Error>(row).ok())
            .find(|row| {
                row.invitation_id == invitation_id
                    && row.organization_id == organization_id
                    && row.status == "pending"
            })
            .map(|row| row.email)
            .ok_or(ManagementError::NotAuthorized)
    }

    fn uuid(&self, now_ms: u64) -> Result<Uuid, ManagementError<T::Error>> {
        uuid_v7(now_ms, &self.randomness).map_err(|_| ManagementError::RandomnessUnavailable)
    }
}


fn map_transport_error<T>(error: T::Error) -> ManagementError<T::Error>
where
    T: PostgresTransport,
{
    if T::violates_constraint(&error, "auth_organization_requires_owner") {
        ManagementError::ProtectedInvariant
    } else {
        ManagementError::Transport(error)
    }
}

fn map_access_model_error<E: StdError + Send + Sync + 'static>(
    error: AccessModelError,
) -> ManagementError<E> {
    match error {
        AccessModelError::UnknownPermission | AccessModelError::RestrictedPermission => {
            ManagementError::RestrictedPermission
        }
        AccessModelError::IncompleteDependencies => ManagementError::InvalidRequest,
    }
}

fn decode_organization<E>(row: &PgRow) -> Result<OrganizationRecord, ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    Ok(OrganizationRecord {
        organization_id: row.required_text("organization_id")?.to_owned(),
        name: row.required_text("name")?.to_owned(),
        slug: row.text("slug")?.unwrap_or("").to_owned(),
        status: row.required_text("status")?.to_owned(),
        role_id: row.required_text("role_id")?.to_owned(),
        permissions: decode_permissions(row)?,
        created_at_ms: to_u64(row.required_i64("created_at_ms")?)?,
    })
}

fn decode_membership<E>(row: &PgRow) -> Result<MembershipRecord, ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    Ok(MembershipRecord {
        organization_id: row.required_text("organization_id")?.to_owned(),
        user_id: row.required_text("user_id")?.to_owned(),
        primary_email: row.required_text("primary_email")?.to_owned(),
        role_id: row.required_text("role_id")?.to_owned(),
        status: row.required_text("status")?.to_owned(),
        joined_at_ms: to_u64(row.required_i64("joined_at_ms")?)?,
    })
}

fn decode_role<E>(row: &PgRow) -> Result<RoleRecord, ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    Ok(RoleRecord {
        organization_id: row.required_text("organization_id")?.to_owned(),
        role_id: row.required_text("role_id")?.to_owned(),
        name: row.required_text("name")?.to_owned(),
        built_in: row.bool("built_in")?.ok_or(ManagementError::InvalidRow)?,
        permissions: decode_permissions(row)?,
    })
}

fn decode_invitation<E>(row: &PgRow) -> Result<InvitationRecord, ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    Ok(InvitationRecord {
        invitation_id: row.required_text("invitation_id")?.to_owned(),
        organization_id: row.required_text("organization_id")?.to_owned(),
        email: row.required_text("normalized_email")?.to_owned(),
        role_id: row.required_text("role_id")?.to_owned(),
        status: row.required_text("status")?.to_owned(),
        expires_at_ms: to_u64(row.required_i64("expires_at_ms")?)?,
    })
}

fn decode_admin_user<E>(row: &PgRow) -> Result<AdminUserRecord, ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    Ok(AdminUserRecord {
        user_id: row.required_text("user_id")?.to_owned(),
        primary_email: row.required_text("primary_email")?.to_owned(),
        status: row.required_text("status")?.to_owned(),
        created_at_ms: to_u64(row.required_i64("created_at_ms")?)?,
    })
}

fn decode_audit<E>(row: &PgRow) -> Result<AuditEventRecord, ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    Ok(AuditEventRecord {
        sequence: to_u64(row.required_i64("sequence")?)?,
        organization_id: row.text("organization_id")?.map(str::to_owned),
        actor_user_id: row.required_text("actor_user_id")?.to_owned(),
        action: row.required_text("action")?.to_owned(),
        resource_type: row.required_text("resource_type")?.to_owned(),
        resource_id: row.required_text("resource_id")?.to_owned(),
        outcome: row.required_text("outcome")?.to_owned(),
        occurred_at_ms: to_u64(row.required_i64("occurred_at_ms")?)?,
    })
}

fn decode_permissions<E>(row: &PgRow) -> Result<Vec<String>, ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    row.json("permissions")?
        .and_then(Value::as_array)
        .ok_or(ManagementError::InvalidRow)?
        .iter()
        .map(|permission| {
            permission
                .as_str()
                .map(str::to_owned)
                .ok_or(ManagementError::InvalidRow)
        })
        .collect()
}

fn parse_uuid<E>(value: &str) -> Result<String, ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    Uuid::parse_str(value)
        .map(|value| value.to_string())
        .map_err(|_| ManagementError::InvalidRequest)
}

fn bounded_name<E>(value: &str, max: usize) -> Result<String, ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let value = value.trim();
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        Err(ManagementError::InvalidRequest)
    } else {
        Ok(value.to_owned())
    }
}

fn validate_role_id<E>(value: &str, allow_built_in: bool) -> Result<(), ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let built_in = matches!(value, "owner" | "admin" | "member" | "viewer");
    if value.is_empty()
        || value.len() > 128
        || (!allow_built_in && built_in)
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
    {
        Err(ManagementError::InvalidRequest)
    } else {
        Ok(())
    }
}

#[cfg(feature = "password")]
fn normalize_email<E>(value: &str) -> Result<String, ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let value = value.trim().to_ascii_lowercase();
    if value.len() > 320
        || value.split_once('@').is_none_or(|(local, domain)| {
            local.is_empty() || domain.is_empty() || !domain.contains('.')
        })
    {
        Err(ManagementError::InvalidRequest)
    } else {
        Ok(value)
    }
}

fn now_ms<C: Clock>(clock: &C) -> u64 {
    clock.now_unix_seconds().saturating_mul(1_000)
}
fn now_value<C: Clock>(clock: &C) -> PgValue {
    i64_value(now_ms(clock))
}
fn i64_value(value: u64) -> PgValue {
    PgValue::I64(i64::try_from(value).unwrap_or(i64::MAX))
}
fn text(value: impl ToString) -> PgValue {
    PgValue::Text(value.to_string())
}
fn to_u64<E>(value: i64) -> Result<u64, ManagementError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    u64::try_from(value).map_err(|_| ManagementError::InvalidRow)
}

fn uuid_v7<R: RandomSource>(now_ms: u64, randomness: &R) -> Result<Uuid, ()> {
    let mut random = [0_u8; UUID_RANDOM_BYTES];
    randomness.fill_bytes(&mut random).map_err(|_| ())?;
    let timestamp = now_ms.min(0x0000_ffff_ffff_ffff).to_be_bytes();
    let mut bytes = [0_u8; 16];
    bytes[..6].copy_from_slice(&timestamp[2..]);
    bytes[6] = 0x70 | (random[0] & 0x0f);
    bytes[7] = random[1];
    bytes[8] = 0x80 | (random[2] & 0x3f);
    bytes[9..].copy_from_slice(&random[3..]);
    Ok(Uuid::from_bytes(bytes))
}

/// Tenant-management workflow failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ManagementError<E: StdError + Send + Sync + 'static> {
    /// Public input violated bounds or identifier contracts.
    #[error("management request is invalid")]
    InvalidRequest,
    /// Session, assurance, membership, or permission failed closed.
    #[error("management operation is not authorized")]
    NotAuthorized,
    /// The operation would remove a final owner or violate account state.
    #[error("operation would violate an ownership or account invariant")]
    ProtectedInvariant,
    /// A custom role is still assigned to active members or pending invitations.
    #[error(
        "custom role is still used by {member_count} active member(s) and {invitation_count} pending invitation(s)"
    )]
    RoleInUse {
        /// Active memberships still assigned this role.
        member_count: u64,
        /// Pending invitations that still grant this role.
        invitation_count: u64,
    },
    /// A custom role requested a system or ownership permission.
    #[error("custom role contains a restricted permission")]
    RestrictedPermission,
    /// An invitation token was missing, expired, consumed, or mismatched.
    #[error("invitation token is invalid or expired")]
    InvalidToken,
    /// Host randomness failed.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// Token or outbox cryptography failed.
    #[error("invitation cryptography failed")]
    Crypto,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL management transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL row decoding failed.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned a structurally invalid result.
    #[error("PostgreSQL returned malformed management data")]
    InvalidRow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn custom_roles_cannot_be_built_ins() {
        assert!(validate_role_id::<std::convert::Infallible>("owner", false).is_err());
        assert!(validate_role_id::<std::convert::Infallible>("billing-editor", false).is_ok());
    }

    #[test]
    fn permission_catalog_is_sorted_and_unique() {
        assert!(
            ORGANIZATION_PERMISSION_CATALOG
                .windows(2)
                .all(|pair| pair[0] < pair[1])
        );
    }

    #[test]
    fn access_model_error_maps_to_management_variants() {
        assert!(matches!(
            map_access_model_error::<std::convert::Infallible>(AccessModelError::UnknownPermission),
            ManagementError::RestrictedPermission
        ));
        assert!(matches!(
            map_access_model_error::<std::convert::Infallible>(
                AccessModelError::RestrictedPermission
            ),
            ManagementError::RestrictedPermission
        ));
        assert!(matches!(
            map_access_model_error::<std::convert::Infallible>(
                AccessModelError::IncompleteDependencies
            ),
            ManagementError::InvalidRequest
        ));
    }

    #[test]
    fn invitation_ids_must_be_uuids() {
        assert!(matches!(
            parse_uuid::<std::convert::Infallible>("not-a-uuid"),
            Err(ManagementError::InvalidRequest)
        ));
        assert!(parse_uuid::<std::convert::Infallible>(
            "0190f0c2-6f3a-7b6e-9c1d-2e4f5a6b7c8d"
        )
        .is_ok());
    }

    #[cfg(feature = "password")]
    #[test]
    fn invitation_ttl_is_seven_days() {
        // Live SQL coverage for revoke/resend: extend tests/postgres_kernel.rs and
        // run via scripts/test-postgres-kernel-live.sh (suite is #[ignore] by default).
        assert_eq!(INVITATION_TTL_MS, 7 * 24 * 60 * 60 * 1_000);
    }

    #[test]
    fn custom_role_delete_rejects_built_in_ids() {
        assert!(matches!(
            validate_role_id::<std::convert::Infallible>("owner", false),
            Err(ManagementError::InvalidRequest)
        ));
        assert!(validate_role_id::<std::convert::Infallible>("billing-editor", false).is_ok());
    }

    #[test]
    fn role_in_use_error_exposes_counts() {
        let error = ManagementError::<std::convert::Infallible>::RoleInUse {
            member_count: 2,
            invitation_count: 1,
        };
        let message = error.to_string();
        assert!(message.contains("2"));
        assert!(message.contains("1"));
        assert!(message.contains("active member"));
        assert!(message.contains("pending invitation"));
    }
}
