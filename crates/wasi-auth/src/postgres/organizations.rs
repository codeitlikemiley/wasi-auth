//! Organization onboarding and session-selection workflows.

use std::error::Error as StdError;

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::{PgRow, PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};
use crate::{
    authentication::{Clock, RandomSource},
    context::{RequestId, SessionId, UserId},
};

const CREATE_ORGANIZATION_SQL: &str = include_str!("create_organization.sql");
const LIST_ORGANIZATIONS_SQL: &str = include_str!("list_organizations.sql");
const SELECT_ORGANIZATION_SQL: &str = include_str!("select_organization.sql");
const IDEMPOTENCY_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const UUID_RANDOM_BYTES: usize = 10;

/// Tenant organization visible to one active member.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OrganizationRecord {
    /// Organization UUID.
    pub organization_id: String,
    /// Display name.
    pub name: String,
    /// Lifecycle status.
    pub status: String,
    /// Current user's assigned role.
    pub role_id: String,
    /// Role-derived permission set.
    pub permissions: Vec<String>,
    /// Creation time in Unix milliseconds.
    pub created_at_ms: u64,
}

/// Idempotent create-organization request bound to an authenticated session.
#[derive(Clone, Debug)]
pub struct CreateOrganizationRequest {
    /// Durable request key.
    pub idempotency_key: String,
    /// Authenticated session.
    pub session_id: SessionId,
    /// Organization display name.
    pub name: String,
    /// Request correlation identifier.
    pub request_id: RequestId,
}

/// PostgreSQL organization workflow service.
pub struct OrganizationService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
}

impl<T, C, R> OrganizationService<T, C, R> {
    /// Assembles the service from concrete runtime dependencies.
    #[must_use]
    pub const fn new(store: PostgresAuthStore<T>, clock: C, randomness: R) -> Self {
        Self {
            store,
            clock,
            randomness,
        }
    }

    /// Returns the relational store used by this service.
    #[must_use]
    pub const fn store(&self) -> &PostgresAuthStore<T> {
        &self.store
    }
}

impl<T, C, R> OrganizationService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Creates built-in roles, owner membership, selected session, audit, and
    /// idempotency result in one statement.
    ///
    /// # Errors
    ///
    /// Returns validation, authentication, idempotency, row, randomness, or
    /// PostgreSQL failures.
    pub async fn create(
        &self,
        request: CreateOrganizationRequest,
    ) -> Result<OrganizationRecord, OrganizationError<T::Error>> {
        let name = request.name.trim();
        if name.is_empty()
            || name.len() > 120
            || name.chars().any(char::is_control)
            || request.idempotency_key.is_empty()
            || request.idempotency_key.len() > 256
        {
            return Err(OrganizationError::InvalidRequest);
        }
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let organization_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| OrganizationError::RandomnessUnavailable)?;
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| OrganizationError::RandomnessUnavailable)?;
        let request_hash = create_request_hash(request.session_id.as_str(), name);
        let rows = self
            .store
            .transport()
            .query(
                CREATE_ORGANIZATION_SQL,
                vec![
                    PgValue::Text(request.idempotency_key),
                    PgValue::Text(request.session_id.as_str().to_owned()),
                    PgValue::Bytes(request_hash.to_vec()),
                    PgValue::Text(organization_id.to_string()),
                    PgValue::Text(name.to_owned()),
                    PgValue::Text(request.session_id.as_str().to_owned()),
                    PgValue::Text(audit_id.to_string()),
                    PgValue::Text(request.request_id.as_str().to_owned()),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::I64(u64_to_i64(now_ms.saturating_add(IDEMPOTENCY_TTL_MS))),
                ],
            )
            .await
            .map_err(OrganizationError::Transport)?;
        let row = rows.first().ok_or(OrganizationError::UnexpectedOutcome)?;
        match row.required_text("outcome")? {
            "created" | "replayed" => decode_organization(row),
            "idempotency_conflict" => Err(OrganizationError::IdempotencyConflict),
            "unauthorized" => Err(OrganizationError::Unauthenticated),
            _ => Err(OrganizationError::UnexpectedOutcome),
        }
    }

    /// Lists active organizations and role permissions for a user.
    ///
    /// # Errors
    ///
    /// Returns invalid identity, malformed row, or PostgreSQL failures.
    pub async fn list(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<OrganizationRecord>, OrganizationError<T::Error>> {
        self.store
            .transport()
            .query(
                LIST_ORGANIZATIONS_SQL,
                vec![PgValue::Text(user_id.as_str().to_owned())],
            )
            .await
            .map_err(OrganizationError::Transport)?
            .iter()
            .map(decode_organization)
            .collect()
    }

    /// Selects one active organization for a session and audits the change.
    ///
    /// # Errors
    ///
    /// Fails closed for missing membership, stale session, or insufficient
    /// assurance for owner/administrator roles.
    pub async fn select(
        &self,
        session_id: &SessionId,
        organization_id: &str,
        request_id: &RequestId,
    ) -> Result<(), OrganizationError<T::Error>> {
        let organization_id =
            Uuid::parse_str(organization_id).map_err(|_| OrganizationError::InvalidRequest)?;
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| OrganizationError::RandomnessUnavailable)?;
        let rows = self
            .store
            .transport()
            .query(
                SELECT_ORGANIZATION_SQL,
                vec![
                    PgValue::Text(session_id.as_str().to_owned()),
                    PgValue::Text(organization_id.to_string()),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::Text(audit_id.to_string()),
                    PgValue::Text(request_id.as_str().to_owned()),
                ],
            )
            .await
            .map_err(OrganizationError::Transport)?;
        if rows
            .first()
            .is_some_and(|row| row.required_text("outcome").ok() == Some("selected"))
        {
            Ok(())
        } else {
            Err(OrganizationError::Unauthenticated)
        }
    }
}

fn decode_organization<E>(row: &PgRow) -> Result<OrganizationRecord, OrganizationError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let permissions = row
        .json("permissions")?
        .and_then(Value::as_array)
        .ok_or(OrganizationError::InvalidRow)?
        .iter()
        .map(|permission| {
            permission
                .as_str()
                .map(str::to_owned)
                .ok_or(OrganizationError::InvalidRow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OrganizationRecord {
        organization_id: row.required_text("organization_id")?.to_owned(),
        name: row.required_text("name")?.to_owned(),
        status: row.required_text("status")?.to_owned(),
        role_id: row.required_text("role_id")?.to_owned(),
        permissions,
        created_at_ms: u64::try_from(row.required_i64("created_at_ms")?)
            .map_err(|_| OrganizationError::InvalidRow)?,
    })
}

fn create_request_hash(session_id: &str, name: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"wasi-auth:create-organization:v1\0");
    digest.update((session_id.len() as u64).to_be_bytes());
    digest.update(session_id.as_bytes());
    digest.update((name.len() as u64).to_be_bytes());
    digest.update(name.as_bytes());
    digest.finalize().into()
}

fn uuid_v7<R>(now_ms: u64, randomness: &R) -> Result<Uuid, ()>
where
    R: RandomSource,
{
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

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

/// Organization workflow failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OrganizationError<E: StdError + Send + Sync + 'static> {
    /// Request fields violated bounds or UUID contracts.
    #[error("organization request is invalid")]
    InvalidRequest,
    /// Session, account, membership, or assurance failed closed.
    #[error("organization operation is not authorized")]
    Unauthenticated,
    /// Idempotency key was reused for a different request.
    #[error("organization idempotency key conflicts with an earlier request")]
    IdempotencyConflict,
    /// Host cryptographic randomness was unavailable.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL organization transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL row failed typed decoding.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned structurally invalid data.
    #[error("PostgreSQL returned malformed organization data")]
    InvalidRow,
    /// PostgreSQL returned an outcome outside the command contract.
    #[error("PostgreSQL returned an unexpected organization outcome")]
    UnexpectedOutcome,
}
