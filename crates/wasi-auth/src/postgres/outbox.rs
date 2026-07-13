//! Durable PostgreSQL outbox leasing and provider-neutral mail dispatch.

use std::{error::Error as StdError, fmt};

use http::Uri;
use serde::Deserialize;
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::{PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};
#[cfg(feature = "spicedb")]
use crate::{
    authentication::RelationshipOperation,
    spicedb::{SpiceDbRelationshipWriter, SpiceDbTransport},
};
use crate::{
    authentication::{Clock, RandomSource, RelationshipOutboxIntent},
    mail::{EmailKind, EmailMessage, Mailer, Recipient},
    postgres::workflows::OutboxSealingKey,
};

const LEASE_OUTBOX_SQL: &str = include_str!("lease_outbox.sql");
const COMPLETE_OUTBOX_SQL: &str = include_str!("complete_outbox.sql");
const RETRY_OUTBOX_SQL: &str = include_str!("retry_outbox.sql");
#[cfg(feature = "spicedb")]
const LOAD_RELATIONSHIP_CONSISTENCY_SQL: &str = include_str!("load_relationship_consistency.sql");
#[cfg(feature = "mail-capture")]
const LOAD_RECENT_DELIVERED_MAIL_SQL: &str = include_str!("load_recent_delivered_mail.sql");
const MAIL_LEASE_MS: u64 = 30_000;
const MAX_MAIL_BATCH: usize = 25;
#[cfg(feature = "spicedb")]
const RELATIONSHIP_LEASE_MS: u64 = 30_000;
#[cfg(feature = "spicedb")]
const MAX_RELATIONSHIP_BATCH: usize = 100;
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
    key_version: Option<String>,
    payload_ciphertext: Vec<u8>,
    relationship: Option<RelationshipOutboxIntent>,
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
            .field(
                "relationship",
                &self.relationship.as_ref().map(|_| "[TYPED]"),
            )
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

    /// Reconstructs the most recent matching development message from the
    /// encrypted durable outbox.
    ///
    /// This avoids relying on process-local capture state, which is not stable
    /// across pooled or short-lived component instances. Callers must still
    /// gate this operation behind validated development configuration.
    ///
    /// # Errors
    ///
    /// Returns a PostgreSQL transport failure. Delivered rows encrypted under
    /// a different historical key are skipped because this development helper
    /// has no key ring and must not block capture polling during key rotation.
    #[cfg(feature = "mail-capture")]
    pub async fn latest_delivered_for_development(
        &self,
        recipient: &Recipient,
        kind: EmailKind,
    ) -> Result<Option<EmailMessage>, MailOutboxError<T::Error>> {
        let rows = self
            .store
            .transport()
            .query(LOAD_RECENT_DELIVERED_MAIL_SQL, Vec::new())
            .await
            .map_err(MailOutboxError::Transport)?;
        for row in &rows {
            let Ok(ciphertext) = row.required_bytes("payload_ciphertext") else {
                continue;
            };
            if ciphertext.is_empty() || ciphertext.len() > 256 * 1_024 {
                continue;
            }
            let (Ok(deduplication_key), Ok(key_version)) = (
                row.required_text("deduplication_key"),
                row.required_text("key_version"),
            ) else {
                continue;
            };
            let Ok(message) =
                self.message_from_encrypted(deduplication_key, key_version, ciphertext)
            else {
                continue;
            };
            if message.recipient() == recipient && message.kind() == kind {
                return Ok(Some(message));
            }
        }
        Ok(None)
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
        self.message_from_encrypted(
            &lease.deduplication_key,
            lease.key_version.as_deref().ok_or(())?,
            &lease.payload_ciphertext,
        )
    }

    fn message_from_encrypted(
        &self,
        deduplication_key: &str,
        key_version: &str,
        payload_ciphertext: &[u8],
    ) -> Result<EmailMessage, ()> {
        let plaintext = Zeroizing::new(
            self.sealing_key
                .open(key_version, payload_ciphertext)
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
            self.public_base_url.one_time_url(path, &payload.token),
            deduplication_key.to_owned(),
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
        key_version: Some(row.required_text("key_version")?.to_owned()),
        payload_ciphertext: ciphertext.to_vec(),
        relationship: None,
        attempt_count: u64::try_from(row.required_i64("attempt_count")?)
            .map_err(|_| MailOutboxError::InvalidRow)?,
        lease_id: Uuid::parse_str(row.required_text("lease_id")?)
            .map_err(|_| MailOutboxError::InvalidRow)?,
    })
}

/// Resource-scoped relationship synchronization state.
#[cfg(feature = "spicedb")]
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationshipConsistency {
    has_unsettled: bool,
    consistency_token: Option<String>,
    resource_revision: Option<u64>,
}

#[cfg(feature = "spicedb")]
impl RelationshipConsistency {
    /// Returns whether a grant, revocation, or dead letter remains unsettled.
    #[must_use]
    pub const fn has_unsettled(&self) -> bool {
        self.has_unsettled
    }

    /// Returns the newest provider token acknowledged for this resource.
    #[must_use]
    pub fn consistency_token(&self) -> Option<&str> {
        self.consistency_token.as_deref()
    }

    /// Returns the newest relationship revision known for this resource.
    #[must_use]
    pub const fn resource_revision(&self) -> Option<u64> {
        self.resource_revision
    }
}

/// Loads synchronization state for exactly one protected resource.
///
/// Callers must deny while [`RelationshipConsistency::has_unsettled`] is true.
/// This prevents one tenant's provider backlog from blocking unrelated tenants.
///
/// # Errors
///
/// Rejects malformed resource identifiers, transport failures, and malformed
/// database rows.
#[cfg(feature = "spicedb")]
pub async fn load_relationship_consistency<T>(
    store: &PostgresAuthStore<T>,
    resource_type: &str,
    resource_id: &str,
) -> Result<RelationshipConsistency, RelationshipConsistencyError<T::Error>>
where
    T: PostgresTransport,
{
    if !valid_relationship_name(resource_type)
        || resource_id.is_empty()
        || resource_id.len() > 1_024
        || resource_id.chars().any(char::is_control)
    {
        return Err(RelationshipConsistencyError::InvalidResource);
    }
    let rows = store
        .transport()
        .query(
            LOAD_RELATIONSHIP_CONSISTENCY_SQL,
            vec![
                PgValue::Text(resource_type.to_owned()),
                PgValue::Text(resource_id.to_owned()),
            ],
        )
        .await
        .map_err(RelationshipConsistencyError::Transport)?;
    let row = rows
        .first()
        .ok_or(RelationshipConsistencyError::InvalidRow)?;
    let has_unsettled = row
        .bool("has_unsettled")?
        .ok_or(RelationshipConsistencyError::InvalidRow)?;
    let consistency_token = row.text("consistency_token")?.map(str::to_owned);
    if consistency_token.as_ref().is_some_and(|token| {
        token.is_empty() || token.len() > 4_096 || token.chars().any(char::is_control)
    }) {
        return Err(RelationshipConsistencyError::InvalidRow);
    }
    let resource_revision = row
        .i64("resource_revision")?
        .map(u64::try_from)
        .transpose()
        .map_err(|_| RelationshipConsistencyError::InvalidRow)?;
    Ok(RelationshipConsistency {
        has_unsettled,
        consistency_token,
        resource_revision,
    })
}

#[cfg(feature = "spicedb")]
fn valid_relationship_name(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

/// Resource-scoped relationship consistency lookup failure.
#[cfg(feature = "spicedb")]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RelationshipConsistencyError<E: StdError + Send + Sync + 'static> {
    /// Resource type or identifier violated the bounded contract.
    #[error("relationship resource is invalid")]
    InvalidResource,
    /// PostgreSQL lookup failed.
    #[error("PostgreSQL relationship consistency lookup failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL returned a typed row-decoding failure.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned malformed synchronization metadata.
    #[error("PostgreSQL returned invalid relationship consistency metadata")]
    InvalidRow,
}

/// One bounded relationship-dispatch pass result.
#[cfg(feature = "spicedb")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct RelationshipDispatchReport {
    /// Rows leased for this pass.
    pub leased: usize,
    /// Relationship writes acknowledged in PostgreSQL.
    pub delivered: usize,
    /// Failures returned to the pending queue.
    pub retried: usize,
    /// Poison or repeatedly failing rows moved to the dead-letter state.
    pub dead_lettered: usize,
}

/// Durable relationship outbox worker backed by the canonical `auth_outbox`.
#[cfg(feature = "spicedb")]
pub struct RelationshipOutboxWorker<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
}

#[cfg(feature = "spicedb")]
impl<T, C, R> RelationshipOutboxWorker<T, C, R> {
    /// Assembles the worker from concrete runtime dependencies.
    #[must_use]
    pub const fn new(store: PostgresAuthStore<T>, clock: C, randomness: R) -> Self {
        Self {
            store,
            clock,
            randomness,
        }
    }

    /// Returns the relational store used by this worker.
    #[must_use]
    pub const fn store(&self) -> &PostgresAuthStore<T> {
        &self.store
    }
}

#[cfg(feature = "spicedb")]
impl<T, C, R> RelationshipOutboxWorker<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Leases and dispatches a bounded relationship batch.
    ///
    /// SpiceDB writes are at-least-once. `TOUCH` and `DELETE` operations make
    /// retry after a lost database acknowledgement safe. Relationship data is
    /// typed relational metadata inserted by the same statement as its source
    /// membership mutation; secret mail payloads remain separately encrypted.
    ///
    /// # Errors
    ///
    /// Returns invalid batch, randomness, row, or PostgreSQL failures. Provider
    /// failures are persisted as retry/dead-letter outcomes.
    pub async fn dispatch<S>(
        &self,
        writer: &SpiceDbRelationshipWriter<S>,
        batch_size: usize,
    ) -> Result<RelationshipDispatchReport, RelationshipOutboxError<T::Error>>
    where
        S: SpiceDbTransport,
    {
        if batch_size == 0 || batch_size > MAX_RELATIONSHIP_BATCH {
            return Err(RelationshipOutboxError::InvalidBatch);
        }
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let leases = self.lease_relationships(batch_size, now_ms).await?;
        let mut report = RelationshipDispatchReport {
            leased: leases.len(),
            ..RelationshipDispatchReport::default()
        };
        let mut valid = Vec::with_capacity(leases.len());
        for lease in leases {
            match self.relationship(&lease) {
                Ok(intent) => valid.push((lease, intent)),
                Err(()) => {
                    let dead = self
                        .retry_relationship(&lease, "invalid_payload", now_ms)
                        .await?;
                    if dead {
                        report.dead_lettered += 1;
                    } else {
                        report.retried += 1;
                    }
                }
            }
        }
        if valid.is_empty() {
            return Ok(report);
        }

        let intents = valid
            .iter()
            .map(|(_, intent)| intent.clone())
            .collect::<Vec<_>>();
        match writer.write(&intents).await {
            Ok(receipt) => {
                for (lease, _) in &valid {
                    self.complete_relationship(lease, receipt.consistency_token(), now_ms)
                        .await?;
                    report.delivered += 1;
                }
            }
            Err(_) => {
                for (lease, _) in &valid {
                    let dead = self
                        .retry_relationship(lease, "provider_failure", now_ms)
                        .await?;
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

    async fn lease_relationships(
        &self,
        batch_size: usize,
        now_ms: u64,
    ) -> Result<Vec<OutboxLease>, RelationshipOutboxError<T::Error>> {
        let lease_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| RelationshipOutboxError::RandomnessUnavailable)?;
        self.store
            .transport()
            .query(
                LEASE_OUTBOX_SQL,
                vec![
                    PgValue::Text("relationship".to_owned()),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::I64(i64::try_from(batch_size).unwrap_or(i64::MAX)),
                    PgValue::Text(lease_id.to_string()),
                    PgValue::I64(u64_to_i64(now_ms.saturating_add(RELATIONSHIP_LEASE_MS))),
                ],
            )
            .await
            .map_err(RelationshipOutboxError::Transport)?
            .iter()
            .map(decode_relationship_lease)
            .collect()
    }

    fn relationship(&self, lease: &OutboxLease) -> Result<RelationshipOutboxIntent, ()> {
        lease.relationship.clone().ok_or(())
    }

    async fn complete_relationship(
        &self,
        lease: &OutboxLease,
        consistency_token: &str,
        now_ms: u64,
    ) -> Result<(), RelationshipOutboxError<T::Error>> {
        if consistency_token.is_empty()
            || consistency_token.len() > 4_096
            || consistency_token.chars().any(char::is_control)
        {
            return Err(RelationshipOutboxError::InvalidConsistencyToken);
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
                    PgValue::Text(consistency_token.to_owned()),
                ],
            )
            .await
            .map_err(RelationshipOutboxError::Transport)?;
        if rows
            .first()
            .is_some_and(|row| row.required_text("outcome").ok() == Some("delivered"))
        {
            Ok(())
        } else {
            Err(RelationshipOutboxError::LeaseLost)
        }
    }

    async fn retry_relationship(
        &self,
        lease: &OutboxLease,
        error_code: &'static str,
        now_ms: u64,
    ) -> Result<bool, RelationshipOutboxError<T::Error>> {
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
            .map_err(RelationshipOutboxError::Transport)?;
        match rows.first().map(|row| row.required_text("outcome")) {
            Some(Ok("pending")) => Ok(false),
            Some(Ok("dead_letter")) => Ok(true),
            _ => Err(RelationshipOutboxError::LeaseLost),
        }
    }
}

#[cfg(feature = "spicedb")]
fn decode_relationship_lease<E>(
    row: &super::PgRow,
) -> Result<OutboxLease, RelationshipOutboxError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    if row.required_text("kind")? != "relationship" {
        return Err(RelationshipOutboxError::InvalidRow);
    }
    let operation = match row.required_text("relationship_operation")? {
        "grant" => RelationshipOperation::Grant,
        "revoke" => RelationshipOperation::Revoke,
        _ => return Err(RelationshipOutboxError::InvalidRow),
    };
    let resource_revision = u64::try_from(row.required_i64("resource_revision")?)
        .map_err(|_| RelationshipOutboxError::InvalidRow)?;
    let relationship = RelationshipOutboxIntent {
        operation,
        resource: format!(
            "{}:{}",
            row.required_text("resource_type")?,
            row.required_text("resource_id")?
        ),
        relation: row.required_text("relation")?.to_owned(),
        subject: format!(
            "{}:{}",
            row.required_text("subject_type")?,
            row.required_text("subject_id")?
        ),
        resource_revision,
        consistency_token: None,
    };
    Ok(OutboxLease {
        outbox_id: Uuid::parse_str(row.required_text("outbox_id")?)
            .map_err(|_| RelationshipOutboxError::InvalidRow)?,
        deduplication_key: row.required_text("deduplication_key")?.to_owned(),
        key_version: None,
        payload_ciphertext: Vec::new(),
        relationship: Some(relationship),
        attempt_count: u64::try_from(row.required_i64("attempt_count")?)
            .map_err(|_| RelationshipOutboxError::InvalidRow)?,
        lease_id: Uuid::parse_str(row.required_text("lease_id")?)
            .map_err(|_| RelationshipOutboxError::InvalidRow)?,
    })
}

/// Durable relationship worker failure.
#[cfg(feature = "spicedb")]
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum RelationshipOutboxError<E: StdError + Send + Sync + 'static> {
    /// Requested lease batch was empty or exceeded 100 records.
    #[error("relationship outbox batch size is invalid")]
    InvalidBatch,
    /// Host cryptographic randomness was unavailable.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL relationship outbox transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL returned a malformed outbox row.
    #[error("PostgreSQL returned a malformed relationship outbox row")]
    InvalidRow,
    /// PostgreSQL returned a typed row-decoding failure.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// SpiceDB returned an invalid consistency token.
    #[error("SpiceDB consistency token is invalid")]
    InvalidConsistencyToken,
    /// A different worker took or completed the lease.
    #[error("relationship outbox lease is no longer owned by this worker")]
    LeaseLost,
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

#[cfg(all(test, feature = "spicedb"))]
mod tests {
    use std::{
        collections::VecDeque,
        convert::Infallible,
        io,
        sync::{Arc, Mutex},
    };

    use futures::executor::block_on;
    use http::{Response, StatusCode, header::CONTENT_TYPE};

    use super::*;
    use crate::{
        postgres::PgRow,
        spicedb::{SpiceDbBearerToken, SpiceDbWriteEndpoint},
    };

    #[derive(Clone, Copy, Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now_unix_seconds(&self) -> u64 {
            1_700_000_000
        }
    }

    #[derive(Clone, Copy, Debug)]
    struct FixedRandom;

    impl RandomSource for FixedRandom {
        type Error = Infallible;

        fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), Self::Error> {
            destination.fill(7);
            Ok(())
        }
    }

    #[derive(Clone, Default)]
    struct FakePostgres {
        state: Arc<Mutex<FakePostgresState>>,
    }

    #[derive(Default)]
    struct FakePostgresState {
        responses: VecDeque<Vec<PgRow>>,
        calls: Vec<(&'static str, Vec<PgValue>)>,
    }

    impl PostgresTransport for FakePostgres {
        type Error = io::Error;

        async fn query(
            &self,
            sql: &'static str,
            parameters: Vec<PgValue>,
        ) -> Result<Vec<PgRow>, Self::Error> {
            let mut state = self.state.lock().expect("fake postgres lock");
            state.calls.push((sql, parameters));
            state.responses.pop_front().ok_or_else(|| {
                io::Error::new(io::ErrorKind::UnexpectedEof, "missing fake response")
            })
        }
    }

    #[derive(Default)]
    struct FakeSpiceDb;

    impl SpiceDbTransport for FakeSpiceDb {
        type Error = io::Error;

        async fn send(
            &self,
            _request: http::Request<Vec<u8>>,
        ) -> Result<Response<Vec<u8>>, Self::Error> {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header(CONTENT_TYPE, "application/json")
                .body(br#"{"writtenAt":{"token":"zed-relationship-one"}}"#.to_vec())
                .expect("fake SpiceDB response"))
        }
    }

    #[test]
    fn relationship_consistency_is_resource_scoped() {
        let postgres = FakePostgres::default();
        {
            let mut state = postgres.state.lock().expect("fake postgres lock");
            state.responses.push_back(vec![PgRow::new([
                ("has_unsettled".to_owned(), PgValue::Bool(false)),
                (
                    "consistency_token".to_owned(),
                    PgValue::Text("zed-org-one".to_owned()),
                ),
                ("resource_revision".to_owned(), PgValue::I64(9)),
            ])]);
        }
        let store = PostgresAuthStore::new(postgres.clone());
        let consistency = block_on(load_relationship_consistency(
            &store,
            "organization",
            "org-one",
        ))
        .expect("relationship consistency");

        assert_eq!(
            consistency,
            RelationshipConsistency {
                has_unsettled: false,
                consistency_token: Some("zed-org-one".to_owned()),
                resource_revision: Some(9),
            }
        );
        let state = postgres.state.lock().expect("fake postgres lock");
        assert_eq!(state.calls.len(), 1);
        assert_eq!(state.calls[0].0, LOAD_RELATIONSHIP_CONSISTENCY_SQL);
        assert_eq!(
            state.calls[0].1,
            vec![
                PgValue::Text("organization".to_owned()),
                PgValue::Text("org-one".to_owned()),
            ]
        );
    }

    #[test]
    fn relationship_worker_uses_canonical_typed_outbox() {
        let outbox_id = Uuid::now_v7();
        let lease_id = Uuid::now_v7();
        let postgres = FakePostgres::default();
        {
            let mut state = postgres.state.lock().expect("fake postgres lock");
            state.responses.push_back(vec![PgRow::new([
                ("outbox_id".to_owned(), PgValue::Text(outbox_id.to_string())),
                ("kind".to_owned(), PgValue::Text("relationship".to_owned())),
                (
                    "deduplication_key".to_owned(),
                    PgValue::Text("relationship:org-one:user-one:7".to_owned()),
                ),
                (
                    "relationship_operation".to_owned(),
                    PgValue::Text("grant".to_owned()),
                ),
                (
                    "resource_type".to_owned(),
                    PgValue::Text("organization".to_owned()),
                ),
                (
                    "resource_id".to_owned(),
                    PgValue::Text("org-one".to_owned()),
                ),
                ("relation".to_owned(), PgValue::Text("member".to_owned())),
                ("subject_type".to_owned(), PgValue::Text("user".to_owned())),
                (
                    "subject_id".to_owned(),
                    PgValue::Text("user-one".to_owned()),
                ),
                ("resource_revision".to_owned(), PgValue::I64(7)),
                ("attempt_count".to_owned(), PgValue::I64(1)),
                ("lease_id".to_owned(), PgValue::Text(lease_id.to_string())),
            ])]);
            state.responses.push_back(vec![PgRow::new([(
                "outcome".to_owned(),
                PgValue::Text("delivered".to_owned()),
            )])]);
        }

        let worker = RelationshipOutboxWorker::new(
            PostgresAuthStore::new(postgres.clone()),
            FixedClock,
            FixedRandom,
        );
        let writer = SpiceDbRelationshipWriter::new(
            SpiceDbWriteEndpoint::new("https://spicedb.example.test/v1/relationships/write")
                .expect("write endpoint"),
            SpiceDbBearerToken::new("provider-secret").expect("bearer token"),
            FakeSpiceDb,
        );
        let report = block_on(worker.dispatch(&writer, 100)).expect("dispatch relationship");

        assert_eq!(
            report,
            RelationshipDispatchReport {
                leased: 1,
                delivered: 1,
                retried: 0,
                dead_lettered: 0,
            }
        );
        let state = postgres.state.lock().expect("fake postgres lock");
        assert_eq!(state.calls.len(), 2);
        assert_eq!(state.calls[0].0, LEASE_OUTBOX_SQL);
        assert_eq!(
            state.calls[0].1.first(),
            Some(&PgValue::Text("relationship".to_owned()))
        );
        assert_eq!(state.calls[1].0, COMPLETE_OUTBOX_SQL);
        assert!(state.responses.is_empty());
    }
}
