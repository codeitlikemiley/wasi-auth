//! Versioned Cedar policy-bundle publication and metadata.

use std::error::Error as StdError;

use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

use super::{PgRow, PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};
use crate::{
    authentication::{Clock, RandomSource},
    cedar::CedarProvider,
    context::{RequestId, SessionId},
};

const LIST_POLICY_BUNDLES_SQL: &str = include_str!("list_policy_bundles.sql");
const LOAD_ACTIVE_POLICY_BUNDLE_SQL: &str = include_str!("load_active_policy_bundle.sql");
const PUBLISH_POLICY_BUNDLE_SQL: &str = include_str!("publish_policy_bundle.sql");
const MAX_POLICY_BYTES: usize = 1024 * 1024;
const MAX_ENTITY_BYTES: usize = 4 * 1024 * 1024;

/// Non-secret immutable policy-bundle metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PolicyBundleRecord {
    /// Content-addressed policy revision.
    pub policy_revision: String,
    /// Lowercase SHA-256 checksum.
    pub checksum_hex: String,
    /// `staged`, `active`, or `retired`.
    pub status: String,
    /// Publishing system administrator UUID.
    pub created_by: String,
    /// Creation timestamp in milliseconds.
    pub created_at_ms: u64,
    /// Activation timestamp in milliseconds, when activated.
    pub activated_at_ms: Option<u64>,
}

/// Complete strictly bounded Cedar bundle selected for authorization.
///
/// The source is intentionally available only through the authenticated store
/// API. Presenters should expose [`PolicyBundleRecord`] metadata instead.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActivePolicyBundle {
    /// Content-addressed policy revision.
    pub policy_revision: String,
    /// Strict Cedar schema source.
    pub cedar_schema: String,
    /// Cedar policy-set source.
    pub cedar_policy: String,
    /// Trusted Cedar entity graph.
    pub entities: Value,
}

impl<T> PostgresAuthStore<T>
where
    T: PostgresTransport,
{
    /// Loads the single active policy bundle, if one has been published.
    ///
    /// # Errors
    ///
    /// Returns a transport or malformed-row failure. Callers must fail closed
    /// instead of falling back after an active revision has been observed.
    pub async fn load_active_policy_bundle(
        &self,
    ) -> Result<Option<ActivePolicyBundle>, PolicyBundleLoadError<T::Error>> {
        let rows = self
            .transport()
            .query(LOAD_ACTIVE_POLICY_BUNDLE_SQL, Vec::new())
            .await
            .map_err(PolicyBundleLoadError::Transport)?;
        rows.first().map(active_policy_from_row).transpose()
    }
}

/// PostgreSQL Cedar policy-bundle service.
pub struct PolicyBundleService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
}

impl<T, C, R> PolicyBundleService<T, C, R> {
    /// Assembles policy administration from persistence, time, and randomness.
    #[must_use]
    pub const fn new(store: PostgresAuthStore<T>, clock: C, randomness: R) -> Self {
        Self {
            store,
            clock,
            randomness,
        }
    }
}

impl<T, C, R> PolicyBundleService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Lists at most 100 policy versions newest first.
    ///
    /// # Errors
    ///
    /// Returns invalid limit, row, or transport failures.
    pub async fn list(
        &self,
        limit: usize,
    ) -> Result<Vec<PolicyBundleRecord>, PolicyBundleServiceError<T::Error>> {
        if !(1..=100).contains(&limit) {
            return Err(PolicyBundleServiceError::InvalidInput);
        }
        self.query(
            LIST_POLICY_BUNDLES_SQL,
            vec![PgValue::I64(i64::try_from(limit).unwrap_or(100))],
        )
        .await?
        .iter()
        .map(policy_from_row)
        .collect()
    }

    /// Atomically retires the prior active policy, activates this validated
    /// bundle, and records the system-admin audit event.
    ///
    /// The caller must validate Cedar schema and policy semantics before this
    /// persistence boundary; this method independently bounds all content.
    ///
    /// # Errors
    ///
    /// Returns invalid content, admin-session, randomness, row, or transport failures.
    pub async fn publish(
        &self,
        session_id: &SessionId,
        cedar_schema: &str,
        cedar_policy: &str,
        entities: Value,
        request_id: &RequestId,
    ) -> Result<PolicyBundleRecord, PolicyBundleServiceError<T::Error>> {
        let entity_bytes =
            serde_json::to_vec(&entities).map_err(|_| PolicyBundleServiceError::InvalidInput)?;
        if cedar_schema.is_empty()
            || cedar_schema.len() > MAX_POLICY_BYTES
            || cedar_policy.is_empty()
            || cedar_policy.len() > MAX_POLICY_BYTES
            || entity_bytes.len() > MAX_ENTITY_BYTES
            || !entities.is_array()
        {
            return Err(PolicyBundleServiceError::InvalidInput);
        }
        let entity_source =
            serde_json::to_string(&entities).map_err(|_| PolicyBundleServiceError::InvalidInput)?;
        CedarProvider::new_validated(
            cedar_policy,
            cedar_schema,
            &entity_source,
            "publication-candidate",
        )
        .map_err(|_| PolicyBundleServiceError::InvalidInput)?;
        let mut digest = Sha256::new();
        digest.update(cedar_schema.as_bytes());
        digest.update([0]);
        digest.update(cedar_policy.as_bytes());
        digest.update([0]);
        digest.update(&entity_bytes);
        let checksum = digest.finalize().to_vec();
        let checksum_hex = hex(&checksum);
        let policy_revision = format!("sha256:{checksum_hex}");
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PolicyBundleServiceError::RandomnessUnavailable)?;
        let rows = self
            .query(
                PUBLISH_POLICY_BUNDLE_SQL,
                vec![
                    text(session_id.as_str()),
                    text(&policy_revision),
                    text(cedar_schema),
                    text(cedar_policy),
                    PgValue::Json(entities),
                    PgValue::Bytes(checksum),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        rows.first()
            .ok_or(PolicyBundleServiceError::InvalidAdminSession)
            .and_then(policy_from_row)
    }

    async fn query(
        &self,
        sql: &'static str,
        parameters: Vec<PgValue>,
    ) -> Result<Vec<PgRow>, PolicyBundleServiceError<T::Error>> {
        self.store
            .transport()
            .query(sql, parameters)
            .await
            .map_err(PolicyBundleServiceError::Transport)
    }
}

fn policy_from_row<E>(row: &PgRow) -> Result<PolicyBundleRecord, PolicyBundleServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    Ok(PolicyBundleRecord {
        policy_revision: row.required_text("policy_revision")?.to_owned(),
        checksum_hex: row.required_text("checksum_hex")?.to_owned(),
        status: row.required_text("status")?.to_owned(),
        created_by: row.required_text("created_by")?.to_owned(),
        created_at_ms: u64::try_from(row.required_i64("created_at_ms")?)
            .map_err(|_| PolicyBundleServiceError::InvalidRow)?,
        activated_at_ms: row
            .i64("activated_at_ms")?
            .map(u64::try_from)
            .transpose()
            .map_err(|_| PolicyBundleServiceError::InvalidRow)?,
    })
}

fn active_policy_from_row<E>(row: &PgRow) -> Result<ActivePolicyBundle, PolicyBundleLoadError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let policy_revision = row.required_text("policy_revision")?.to_owned();
    let cedar_schema = row.required_text("cedar_schema")?.to_owned();
    let cedar_policy = row.required_text("cedar_policy")?.to_owned();
    let entities = row
        .json("entities")?
        .cloned()
        .ok_or(PolicyBundleLoadError::InvalidRow)?;
    if cedar_schema.is_empty()
        || cedar_schema.len() > MAX_POLICY_BYTES
        || cedar_policy.is_empty()
        || cedar_policy.len() > MAX_POLICY_BYTES
        || serde_json::to_vec(&entities).map_or(true, |value| value.len() > MAX_ENTITY_BYTES)
        || !entities.is_array()
    {
        return Err(PolicyBundleLoadError::InvalidRow);
    }
    Ok(ActivePolicyBundle {
        policy_revision,
        cedar_schema,
        cedar_policy,
        entities,
    })
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn uuid_v7<R: RandomSource>(now_ms: u64, randomness: &R) -> Result<Uuid, ()> {
    let mut random = [0_u8; 10];
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

fn text(value: impl ToString) -> PgValue {
    PgValue::Text(value.to_string())
}

fn i64_value(value: u64) -> PgValue {
    PgValue::I64(i64::try_from(value).unwrap_or(i64::MAX))
}

/// Cedar policy-bundle administration failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PolicyBundleServiceError<E: StdError + Send + Sync + 'static> {
    /// Policy, schema, entity data, or limit was invalid or unbounded.
    #[error("policy bundle input is invalid")]
    InvalidInput,
    /// Session was not a live AAL2 system-administrator session.
    #[error("policy publication requires an AAL2 system administrator")]
    InvalidAdminSession,
    /// Host randomness failed.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL policy transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL row decoding failed.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned malformed policy metadata.
    #[error("PostgreSQL returned malformed policy metadata")]
    InvalidRow,
}

/// Active Cedar bundle loading failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PolicyBundleLoadError<E: StdError + Send + Sync + 'static> {
    /// PostgreSQL transport failed.
    #[error("PostgreSQL policy transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL returned an undecodable row.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned an invalid or unbounded bundle.
    #[error("PostgreSQL returned an invalid active policy bundle")]
    InvalidRow,
}
