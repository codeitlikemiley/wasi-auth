//! Durable PostgreSQL outbox leasing and provider-neutral mail dispatch.

use std::{error::Error as StdError, fmt};

use http::Uri;
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::{PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};
use crate::{
    authentication::{Clock, RandomSource},
    mail::{EmailKind, EmailMessage, Mailer, Recipient},
    postgres::workflows::OutboxSealingKey,
};

const LEASE_OUTBOX_SQL: &str = include_str!("lease_outbox.sql");
const COMPLETE_OUTBOX_SQL: &str = include_str!("complete_outbox.sql");
const RETRY_OUTBOX_SQL: &str = include_str!("retry_outbox.sql");
const MAIL_LEASE_MS: u64 = 30_000;
const MAX_MAIL_BATCH: usize = 25;
const MAX_ATTEMPTS: u64 = 8;
const UUID_RANDOM_BYTES: usize = 10;

/// Validated public application origin used in transactional mail links.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PublicBaseUrl(String);

impl PublicBaseUrl {
    /// Parses an HTTPS origin or loopback HTTP origin.
    ///
    /// # Errors
    ///
    /// Rejects credentials, query/fragment data, non-root paths, and insecure
    /// non-loopback origins.
    pub fn new(value: &str) -> Result<Self, PublicBaseUrlError> {
        let uri = value
            .parse::<Uri>()
            .map_err(|_| PublicBaseUrlError::Invalid)?;
        let scheme = uri.scheme_str().ok_or(PublicBaseUrlError::Invalid)?;
        let authority = uri.authority().ok_or(PublicBaseUrlError::Invalid)?;
        let host = uri.host().ok_or(PublicBaseUrlError::Invalid)?;
        let secure = scheme == "https";
        let loopback = scheme == "http" && matches!(host, "localhost" | "127.0.0.1" | "[::1]");
        if (!secure && !loopback)
            || authority.as_str().contains('@')
            || uri.query().is_some()
            || uri.path_and_query().is_some_and(|path| path.path() != "/")
        {
            return Err(PublicBaseUrlError::Invalid);
        }
        Ok(Self(value.trim_end_matches('/').to_owned()))
    }

    fn one_time_url(&self, path: &str, token: &str) -> String {
        format!("{}{path}?token={token}", self.0)
    }
}

/// Invalid public mail-link origin.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PublicBaseUrlError {
    /// URL violated the origin contract.
    #[error("public base URL must be an HTTPS origin or loopback HTTP origin")]
    Invalid,
}

/// Redacted durable outbox lease.
struct OutboxLease {
    outbox_id: Uuid,
    deduplication_key: String,
    key_version: String,
    payload_ciphertext: Vec<u8>,
    attempt_count: u64,
    lease_id: Uuid,
}

impl fmt::Debug for OutboxLease {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboxLease")
            .field("outbox_id", &self.outbox_id)
            .field("deduplication_key", &self.deduplication_key)
            .field("key_version", &self.key_version)
            .field("payload_ciphertext", &"[REDACTED]")
            .field("attempt_count", &self.attempt_count)
            .field("lease_id", &self.lease_id)
            .finish()
    }
}

impl Drop for OutboxLease {
    fn drop(&mut self) {
        self.payload_ciphertext.zeroize();
    }
}

#[derive(Deserialize)]
struct MailPayload {
    version: u8,
    kind: String,
    recipient: String,
    token: String,
    redirect_uri: String,
}

impl Drop for MailPayload {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// One bounded mail-dispatch pass result.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct MailDispatchReport {
    /// Rows leased for this pass.
    pub leased: usize,
    /// Provider deliveries acknowledged in PostgreSQL.
    pub delivered: usize,
    /// Failures returned to the pending queue.
    pub retried: usize,
    /// Poison/permanently failing records moved to the dead-letter state.
    pub dead_lettered: usize,
}

/// Durable mail outbox worker.
pub struct MailOutboxWorker<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
    sealing_key: OutboxSealingKey,
    public_base_url: PublicBaseUrl,
}

impl<T, C, R> MailOutboxWorker<T, C, R> {
    /// Assembles the worker from concrete runtime dependencies.
    #[must_use]
    pub const fn new(
        store: PostgresAuthStore<T>,
        clock: C,
        randomness: R,
        sealing_key: OutboxSealingKey,
        public_base_url: PublicBaseUrl,
    ) -> Self {
        Self {
            store,
            clock,
            randomness,
            sealing_key,
            public_base_url,
        }
    }

    /// Returns the relational store used by this worker.
    #[must_use]
    pub const fn store(&self) -> &PostgresAuthStore<T> {
        &self.store
    }
}

impl<T, C, R> MailOutboxWorker<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Leases and dispatches a bounded mail batch.
    ///
    /// Provider failures are persisted as retry/dead-letter outcomes. Database
    /// failures abort the pass so a successful provider call can be retried
    /// with the same deduplication key.
    ///
    /// # Errors
    ///
    /// Returns invalid batch, randomness, row, or PostgreSQL failures.
    pub async fn dispatch<M>(
        &self,
        mailer: &M,
        batch_size: usize,
    ) -> Result<MailDispatchReport, MailOutboxError<T::Error>>
    where
        M: Mailer,
    {
        if batch_size == 0 || batch_size > MAX_MAIL_BATCH {
            return Err(MailOutboxError::InvalidBatch);
        }
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let leases = self.lease(batch_size, now_ms).await?;
        let mut report = MailDispatchReport {
            leased: leases.len(),
            ..MailDispatchReport::default()
        };
        for lease in leases {
            let message = self.message(&lease);
            match message {
                Ok(message) => match mailer.send(&message).await {
                    Ok(delivery_id) => {
                        self.complete(&lease, delivery_id.as_str(), now_ms).await?;
                        report.delivered += 1;
                    }
                    Err(_) => {
                        let dead = self.retry(&lease, "mail_transport", now_ms).await?;
                        if dead {
                            report.dead_lettered += 1;
                        } else {
                            report.retried += 1;
                        }
                    }
                },
                Err(_) => {
                    let dead = self.retry(&lease, "invalid_payload", now_ms).await?;
                    if dead {
                        report.dead_lettered += 1;
                    } else {
                        report.retried += 1;
                    }
                }
            }
        }
        Ok(report)
    }

    async fn lease(
        &self,
        batch_size: usize,
        now_ms: u64,
    ) -> Result<Vec<OutboxLease>, MailOutboxError<T::Error>> {
        let lease_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| MailOutboxError::RandomnessUnavailable)?;
        self.store
            .transport()
            .query(
                LEASE_OUTBOX_SQL,
                vec![
                    PgValue::Text("mail".to_owned()),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::I64(i64::try_from(batch_size).unwrap_or(i64::MAX)),
                    PgValue::Text(lease_id.to_string()),
                    PgValue::I64(u64_to_i64(now_ms.saturating_add(MAIL_LEASE_MS))),
                ],
            )
            .await
            .map_err(MailOutboxError::Transport)?
            .iter()
            .map(decode_lease)
            .collect()
    }

    fn message(&self, lease: &OutboxLease) -> Result<EmailMessage, ()> {
        let plaintext = Zeroizing::new(
            self.sealing_key
                .open(&lease.key_version, &lease.payload_ciphertext)
                .map_err(|_| ())?,
        );
        let payload = serde_json::from_slice::<MailPayload>(&plaintext).map_err(|_| ())?;
        if payload.version != 1
            || !payload.redirect_uri.starts_with('/')
            || payload.redirect_uri.starts_with("//")
        {
            return Err(());
        }
        let (kind, subject, path) = match payload.kind.as_str() {
            "email_verification" => (
                EmailKind::Verification,
                "Verify your email",
                "/verify-email",
            ),
            "password_reset" => (
                EmailKind::PasswordReset,
                "Reset your password",
                "/reset-password",
            ),
            "invitation" => (
                EmailKind::Invitation,
                "Organization invitation",
                "/invitations/accept",
            ),
            _ => return Err(()),
        };
        let recipient = Recipient::new(payload.recipient.clone()).map_err(|_| ())?;
        EmailMessage::new(
            kind,
            recipient,
            subject,
            format!(
                "Open this one-time link: {}",
                self.public_base_url.one_time_url(path, &payload.token)
            ),
            lease.deduplication_key.clone(),
        )
        .map_err(|_| ())
    }

    async fn complete(
        &self,
        lease: &OutboxLease,
        delivery_id: &str,
        now_ms: u64,
    ) -> Result<(), MailOutboxError<T::Error>> {
        if delivery_id.is_empty()
            || delivery_id.len() > 512
            || delivery_id.chars().any(char::is_control)
        {
            return Err(MailOutboxError::InvalidDeliveryId);
        }
        let rows = self
            .store
            .transport()
            .query(
                COMPLETE_OUTBOX_SQL,
                vec![
                    PgValue::Text(lease.outbox_id.to_string()),
                    PgValue::Text(lease.lease_id.to_string()),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::Text(delivery_id.to_owned()),
                ],
            )
            .await
            .map_err(MailOutboxError::Transport)?;
        if rows
            .first()
            .is_some_and(|row| row.required_text("outcome").ok() == Some("delivered"))
        {
            Ok(())
        } else {
            Err(MailOutboxError::LeaseLost)
        }
    }

    async fn retry(
        &self,
        lease: &OutboxLease,
        error_code: &'static str,
        now_ms: u64,
    ) -> Result<bool, MailOutboxError<T::Error>> {
        let exponent = lease.attempt_count.min(10) as u32;
        let delay_ms = 1_000_u64.saturating_mul(2_u64.saturating_pow(exponent));
        let rows = self
            .store
            .transport()
            .query(
                RETRY_OUTBOX_SQL,
                vec![
                    PgValue::Text(lease.outbox_id.to_string()),
                    PgValue::Text(lease.lease_id.to_string()),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::I64(u64_to_i64(now_ms.saturating_add(delay_ms))),
                    PgValue::Text(error_code.to_owned()),
                    PgValue::I64(u64_to_i64(MAX_ATTEMPTS)),
                ],
            )
            .await
            .map_err(MailOutboxError::Transport)?;
        match rows.first().map(|row| row.required_text("outcome")) {
            Some(Ok("pending")) => Ok(false),
            Some(Ok("dead_letter")) => Ok(true),
            _ => Err(MailOutboxError::LeaseLost),
        }
    }
}

fn decode_lease<E>(row: &super::PgRow) -> Result<OutboxLease, MailOutboxError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    if row.required_text("kind")? != "mail" {
        return Err(MailOutboxError::InvalidRow);
    }
    let ciphertext = row.required_bytes("payload_ciphertext")?;
    if ciphertext.is_empty() || ciphertext.len() > 256 * 1_024 {
        return Err(MailOutboxError::InvalidRow);
    }
    Ok(OutboxLease {
        outbox_id: Uuid::parse_str(row.required_text("outbox_id")?)
            .map_err(|_| MailOutboxError::InvalidRow)?,
        deduplication_key: row.required_text("deduplication_key")?.to_owned(),
        key_version: row.required_text("key_version")?.to_owned(),
        payload_ciphertext: ciphertext.to_vec(),
        attempt_count: u64::try_from(row.required_i64("attempt_count")?)
            .map_err(|_| MailOutboxError::InvalidRow)?,
        lease_id: Uuid::parse_str(row.required_text("lease_id")?)
            .map_err(|_| MailOutboxError::InvalidRow)?,
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

/// Durable mail worker failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MailOutboxError<E: StdError + Send + Sync + 'static> {
    /// Requested lease batch was empty or exceeded 25 records.
    #[error("mail outbox batch size is invalid")]
    InvalidBatch,
    /// Host cryptographic randomness was unavailable.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL outbox transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL returned a malformed outbox row.
    #[error("PostgreSQL returned a malformed outbox row")]
    InvalidRow,
    /// PostgreSQL returned a typed row-decoding failure.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// Provider delivery identifier violated bounds.
    #[error("mail provider delivery identifier is invalid")]
    InvalidDeliveryId,
    /// A different worker took or completed the lease.
    #[error("mail outbox lease is no longer owned by this worker")]
    LeaseLost,
}
