//! Authoritative account-session listing and revocation.

use std::error::Error as StdError;

use thiserror::Error;
use uuid::Uuid;

use super::{PgRow, PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};
use crate::{
    authentication::{Clock, RandomSource},
    context::{RequestId, SessionId, UserId},
};

const LIST_SESSIONS_SQL: &str = include_str!("list_sessions.sql");
const REVOKE_SESSION_SQL: &str = include_str!("revoke_session.sql");
const UUID_RANDOM_BYTES: usize = 10;

/// Active session visible on the account security page.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AccountSessionRecord {
    /// Opaque session identifier.
    pub session_id: SessionId,
    /// Selected organization, if any.
    pub organization_id: Option<String>,
    /// Stored assurance string.
    pub assurance: String,
    /// Issue time in Unix milliseconds.
    pub created_at_ms: u64,
    /// Expiry time in Unix milliseconds.
    pub expires_at_ms: u64,
}

/// Relational account-session service.
pub struct SessionService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
}

impl<T, C, R> SessionService<T, C, R> {
    /// Assembles the service from concrete runtime dependencies.
    #[must_use]
    pub const fn new(store: PostgresAuthStore<T>, clock: C, randomness: R) -> Self {
        Self {
            store,
            clock,
            randomness,
        }
    }

    /// Returns the relational store.
    #[must_use]
    pub const fn store(&self) -> &PostgresAuthStore<T> {
        &self.store
    }
}

impl<T, C, R> SessionService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Lists up to 100 active sessions for one authenticated user.
    ///
    /// # Errors
    ///
    /// Returns malformed row or PostgreSQL failures.
    pub async fn list(
        &self,
        user_id: &UserId,
    ) -> Result<Vec<AccountSessionRecord>, SessionServiceError<T::Error>> {
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        self.store
            .transport()
            .query(
                LIST_SESSIONS_SQL,
                vec![
                    PgValue::Text(user_id.as_str().to_owned()),
                    PgValue::I64(u64_to_i64(now_ms)),
                ],
            )
            .await
            .map_err(SessionServiceError::Transport)?
            .iter()
            .map(decode_session)
            .collect()
    }

    /// Revokes one session owned by the actor's account and its refresh tokens.
    ///
    /// # Errors
    ///
    /// Fails closed for a stale actor, another user's target, randomness,
    /// malformed outcome, or PostgreSQL failure.
    pub async fn revoke(
        &self,
        target_session_id: &SessionId,
        actor_session_id: &SessionId,
        request_id: &RequestId,
    ) -> Result<(), SessionServiceError<T::Error>> {
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| SessionServiceError::RandomnessUnavailable)?;
        let rows = self
            .store
            .transport()
            .query(
                REVOKE_SESSION_SQL,
                vec![
                    PgValue::Text(target_session_id.as_str().to_owned()),
                    PgValue::Text(actor_session_id.as_str().to_owned()),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::Text(audit_id.to_string()),
                    PgValue::Text(request_id.as_str().to_owned()),
                ],
            )
            .await
            .map_err(SessionServiceError::Transport)?;
        if rows
            .first()
            .is_some_and(|row| row.required_text("outcome").ok() == Some("revoked"))
        {
            Ok(())
        } else {
            Err(SessionServiceError::NotAuthorized)
        }
    }
}

fn decode_session<E>(row: &PgRow) -> Result<AccountSessionRecord, SessionServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let assurance = row.required_text("assurance")?;
    if !matches!(assurance, "aal1" | "aal2" | "aal3") {
        return Err(SessionServiceError::InvalidRow);
    }
    Ok(AccountSessionRecord {
        session_id: SessionId::new(row.required_text("session_id")?)
            .map_err(|_| SessionServiceError::InvalidRow)?,
        organization_id: row.text("organization_id")?.map(str::to_owned),
        assurance: assurance.to_owned(),
        created_at_ms: u64::try_from(row.required_i64("created_at_ms")?)
            .map_err(|_| SessionServiceError::InvalidRow)?,
        expires_at_ms: u64::try_from(row.required_i64("expires_at_ms")?)
            .map_err(|_| SessionServiceError::InvalidRow)?,
    })
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

/// Account-session service failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SessionServiceError<E: StdError + Send + Sync + 'static> {
    /// Actor or target session was unavailable or did not share an account.
    #[error("session operation is not authorized")]
    NotAuthorized,
    /// Host cryptographic randomness was unavailable.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL session transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL returned a typed row-decoding failure.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned structurally invalid session data.
    #[error("PostgreSQL returned malformed session data")]
    InvalidRow,
}
