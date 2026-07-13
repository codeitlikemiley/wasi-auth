//! Signing-key lifecycle metadata with externally referenced private material.

use std::error::Error as StdError;

use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

use super::{PgRow, PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};
use crate::{
    authentication::{Clock, RandomSource},
    context::{RequestId, SessionId},
};

use super::tokens::JwtKeyRing;

const SYNC_SIGNING_KEYS_SQL: &str = include_str!("sync_signing_keys.sql");
const LIST_SIGNING_KEYS_SQL: &str = include_str!("list_signing_key_metadata.sql");
const ROTATE_SIGNING_KEY_SQL: &str = include_str!("rotate_signing_key.sql");

/// Non-secret signing-key lifecycle record.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningKeyRecord {
    /// Key identifier.
    pub key_id: String,
    /// Signing algorithm.
    pub algorithm: String,
    /// `next`, `active`, `retired`, or `revoked`.
    pub status: String,
    /// Public JWK or development symmetric-key marker.
    pub public_jwk: Value,
    /// Secret-source version.
    pub key_version: String,
    /// Non-secret external secret reference.
    pub secret_reference: String,
    /// Creation timestamp in milliseconds.
    pub created_at_ms: u64,
    /// Activation timestamp in milliseconds.
    pub activated_at_ms: Option<u64>,
    /// Retirement timestamp in milliseconds.
    pub retired_at_ms: Option<u64>,
    /// Revocation timestamp in milliseconds.
    pub revoked_at_ms: Option<u64>,
}

/// Successful signing-key activation metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SigningKeyRotation {
    /// Activated key.
    pub key: SigningKeyRecord,
    /// Previously active key, when one existed.
    pub previous_key_id: Option<String>,
}

/// PostgreSQL signing-key lifecycle service.
pub struct SigningKeyService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
}

impl<T, C, R> SigningKeyService<T, C, R> {
    /// Assembles lifecycle administration from persistence, time, and randomness.
    #[must_use]
    pub const fn new(store: PostgresAuthStore<T>, clock: C, randomness: R) -> Self {
        Self {
            store,
            clock,
            randomness,
        }
    }
}

impl<T, C, R> SigningKeyService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Idempotently synchronizes configured non-secret descriptors, preserving
    /// lifecycle statuses already changed by administrators.
    ///
    /// # Errors
    ///
    /// Returns malformed descriptor, row, or transport failures.
    pub async fn synchronize(
        &self,
        key_ring: &JwtKeyRing,
        key_version: &str,
    ) -> Result<Vec<SigningKeyRecord>, SigningKeyServiceError<T::Error>> {
        if key_version.is_empty()
            || key_version.len() > 128
            || key_version.chars().any(char::is_control)
        {
            return Err(SigningKeyServiceError::InvalidInput);
        }
        let descriptors = key_ring.descriptors();
        let rows = self
            .query(
                SYNC_SIGNING_KEYS_SQL,
                vec![
                    PgValue::Json(
                        serde_json::to_value(&descriptors)
                            .map_err(|_| SigningKeyServiceError::InvalidInput)?,
                    ),
                    text(key_version),
                    i64_value(self.clock.now_unix_seconds().saturating_mul(1_000)),
                ],
            )
            .await?;
        let synchronized = rows
            .first()
            .ok_or(SigningKeyServiceError::InvalidRow)?
            .required_i64("synced_count")?;
        if usize::try_from(synchronized).ok() != Some(descriptors.len()) {
            return Err(SigningKeyServiceError::InvalidInput);
        }
        self.list().await
    }

    /// Lists authoritative lifecycle metadata.
    ///
    /// # Errors
    ///
    /// Returns malformed-row or PostgreSQL transport failures.
    pub async fn list(&self) -> Result<Vec<SigningKeyRecord>, SigningKeyServiceError<T::Error>> {
        self.query(LIST_SIGNING_KEYS_SQL, Vec::new())
            .await?
            .iter()
            .map(signing_key_from_row)
            .collect()
    }

    /// Applies database lifecycle statuses to configured in-process key material.
    ///
    /// # Errors
    ///
    /// Rejects a missing/ambiguous active signer, malformed rows, or transport failures.
    pub async fn apply_authoritative_statuses(
        &self,
        key_ring: &mut JwtKeyRing,
    ) -> Result<(), SigningKeyServiceError<T::Error>> {
        let statuses = self
            .list()
            .await?
            .into_iter()
            .map(|record| (record.key_id, record.status))
            .collect::<Vec<_>>();
        key_ring
            .apply_statuses(&statuses)
            .map_err(|_| SigningKeyServiceError::InvalidLifecycle)
    }

    /// Atomically activates one configured key and audits the AAL2 system admin.
    ///
    /// # Errors
    ///
    /// Returns invalid key/session, lifecycle, randomness, row, or transport failures.
    pub async fn rotate(
        &self,
        session_id: &SessionId,
        key_id: &str,
        retire_previous: bool,
        request_id: &RequestId,
    ) -> Result<SigningKeyRotation, SigningKeyServiceError<T::Error>> {
        if !valid_key_id(key_id) {
            return Err(SigningKeyServiceError::InvalidInput);
        }
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| SigningKeyServiceError::RandomnessUnavailable)?;
        let rows = self
            .query(
                ROTATE_SIGNING_KEY_SQL,
                vec![
                    text(session_id.as_str()),
                    text(key_id),
                    PgValue::Bool(retire_previous),
                    text(audit_id),
                    i64_value(now_ms),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        let row = rows
            .first()
            .ok_or(SigningKeyServiceError::InvalidAdminOrKey)?;
        let previous_key_id = row.text("previous_key_id")?.map(str::to_owned);
        let key = self
            .list()
            .await?
            .into_iter()
            .find(|record| record.key_id == key_id && record.status == "active")
            .ok_or(SigningKeyServiceError::InvalidLifecycle)?;
        Ok(SigningKeyRotation {
            key,
            previous_key_id,
        })
    }

    async fn query(
        &self,
        sql: &'static str,
        parameters: Vec<PgValue>,
    ) -> Result<Vec<PgRow>, SigningKeyServiceError<T::Error>> {
        self.store
            .transport()
            .query(sql, parameters)
            .await
            .map_err(SigningKeyServiceError::Transport)
    }
}

fn signing_key_from_row<E>(row: &PgRow) -> Result<SigningKeyRecord, SigningKeyServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    Ok(SigningKeyRecord {
        key_id: row.required_text("key_id")?.to_owned(),
        algorithm: row.required_text("algorithm")?.to_owned(),
        status: row.required_text("status")?.to_owned(),
        public_jwk: row
            .json("public_jwk")?
            .cloned()
            .ok_or(SigningKeyServiceError::InvalidRow)?,
        key_version: row.required_text("key_version")?.to_owned(),
        secret_reference: row.required_text("secret_reference")?.to_owned(),
        created_at_ms: unsigned(row, "created_at_ms")?,
        activated_at_ms: optional_unsigned(row, "activated_at_ms")?,
        retired_at_ms: optional_unsigned(row, "retired_at_ms")?,
        revoked_at_ms: optional_unsigned(row, "revoked_at_ms")?,
    })
}

fn unsigned<E>(row: &PgRow, column: &'static str) -> Result<u64, SigningKeyServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    u64::try_from(row.required_i64(column)?).map_err(|_| SigningKeyServiceError::InvalidRow)
}

fn optional_unsigned<E>(
    row: &PgRow,
    column: &'static str,
) -> Result<Option<u64>, SigningKeyServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    row.i64(column)?
        .map(u64::try_from)
        .transpose()
        .map_err(|_| SigningKeyServiceError::InvalidRow)
}

fn valid_key_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
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

/// Signing-key persistence or lifecycle failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SigningKeyServiceError<E: StdError + Send + Sync + 'static> {
    /// Key identifier, key version, or descriptor set was invalid.
    #[error("signing-key input is invalid")]
    InvalidInput,
    /// Session lacked AAL2 system-admin authority or the key was unavailable.
    #[error("signing-key administration is not authorized")]
    InvalidAdminOrKey,
    /// Lifecycle metadata did not identify exactly one configured active signer.
    #[error("signing-key lifecycle is invalid")]
    InvalidLifecycle,
    /// Host randomness failed.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL signing-key transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL row decoding failed.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned malformed signing-key data.
    #[error("PostgreSQL returned malformed signing-key metadata")]
    InvalidRow,
}
