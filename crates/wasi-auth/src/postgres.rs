//! PostgreSQL-only relational authentication kernel.
//!
//! Every mutation is expressed as one bounded, parameterized PostgreSQL
//! statement. PostgreSQL supplies the atomic boundary; callers cannot compose
//! arbitrary event, projection, secret, or outbox mutations.

use std::{collections::BTreeMap, error::Error as StdError, fmt, future::Future};

use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;

#[cfg(any(feature = "oauth", feature = "passkeys"))]
pub mod flows;
pub mod management;
#[cfg(all(feature = "mfa", feature = "password"))]
pub mod mfa;
#[cfg(feature = "postgres-native")]
pub mod native;
#[cfg(feature = "oauth")]
pub mod oauth;
pub mod organizations;
#[cfg(feature = "password")]
pub mod outbox;
#[cfg(feature = "passkeys")]
pub mod passkeys;
#[cfg(feature = "cedar")]
pub mod policy;
pub mod rate_limits;
pub mod sessions;
#[cfg(all(feature = "jwt", feature = "password"))]
pub mod signing;
#[cfg(feature = "postgres-spin")]
pub mod spin;
#[cfg(all(feature = "jwt", feature = "password"))]
pub mod tokens;
#[cfg(feature = "password")]
pub mod workflows;

use crate::context::{
    AuthenticationAssurance, AuthorizationSnapshot, OrganizationId, PolicyRevision, Principal,
    RequestId, RoleId, SessionId, UserId, ValidatedContextParts, VerifiedAuthContext,
    VerifiedRequestContext,
};

const REGISTER_PASSWORD_SQL: &str = include_str!("postgres/register_password.sql");
const REGISTRATION_REPLAY_SQL: &str = include_str!("postgres/registration_replay.sql");
const LOAD_REQUEST_CONTEXT_SQL: &str = include_str!("postgres/load_request_context.sql");
#[cfg(all(feature = "jwt", feature = "password"))]
const LOAD_REQUEST_FINGERPRINT_SQL: &str = include_str!("postgres/load_request_fingerprint.sql");

/// Parameter accepted by a PostgreSQL transport.
#[derive(Clone, Debug, PartialEq)]
#[non_exhaustive]
pub enum PgValue {
    /// SQL `NULL`.
    Null,
    /// Boolean value.
    Bool(bool),
    /// Signed 64-bit integer.
    I64(i64),
    /// UTF-8 text.
    Text(String),
    /// Binary bytes.
    Bytes(Vec<u8>),
    /// Structured JSON value encoded as PostgreSQL `JSONB`.
    Json(Value),
}

/// Materialized PostgreSQL row keyed by column name.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct PgRow {
    values: BTreeMap<String, PgValue>,
}

impl PgRow {
    /// Constructs a row from decoded column values.
    #[must_use]
    pub fn new(values: impl IntoIterator<Item = (String, PgValue)>) -> Self {
        Self {
            values: values.into_iter().collect(),
        }
    }

    fn text(&self, column: &'static str) -> Result<Option<&str>, RowDecodeError> {
        match self.values.get(column) {
            Some(PgValue::Text(value)) => Ok(Some(value)),
            Some(PgValue::Null) | None => Ok(None),
            Some(_) => Err(RowDecodeError::WrongType(column)),
        }
    }

    fn required_text(&self, column: &'static str) -> Result<&str, RowDecodeError> {
        self.text(column)?.ok_or(RowDecodeError::Missing(column))
    }

    fn i64(&self, column: &'static str) -> Result<Option<i64>, RowDecodeError> {
        match self.values.get(column) {
            Some(PgValue::I64(value)) => Ok(Some(*value)),
            Some(PgValue::Null) | None => Ok(None),
            Some(_) => Err(RowDecodeError::WrongType(column)),
        }
    }

    fn required_i64(&self, column: &'static str) -> Result<i64, RowDecodeError> {
        self.i64(column)?.ok_or(RowDecodeError::Missing(column))
    }

    #[cfg(any(feature = "password", feature = "oauth", feature = "passkeys"))]
    fn bytes(&self, column: &'static str) -> Result<Option<&[u8]>, RowDecodeError> {
        match self.values.get(column) {
            Some(PgValue::Bytes(value)) => Ok(Some(value)),
            Some(PgValue::Null) | None => Ok(None),
            Some(_) => Err(RowDecodeError::WrongType(column)),
        }
    }

    #[cfg(any(feature = "password", feature = "oauth", feature = "passkeys"))]
    fn required_bytes(&self, column: &'static str) -> Result<&[u8], RowDecodeError> {
        self.bytes(column)?.ok_or(RowDecodeError::Missing(column))
    }

    fn bool(&self, column: &'static str) -> Result<Option<bool>, RowDecodeError> {
        match self.values.get(column) {
            Some(PgValue::Bool(value)) => Ok(Some(*value)),
            Some(PgValue::Null) | None => Ok(None),
            Some(_) => Err(RowDecodeError::WrongType(column)),
        }
    }

    fn json(&self, column: &'static str) -> Result<Option<&Value>, RowDecodeError> {
        match self.values.get(column) {
            Some(PgValue::Json(value)) => Ok(Some(value)),
            Some(PgValue::Null) | None => Ok(None),
            Some(_) => Err(RowDecodeError::WrongType(column)),
        }
    }
}

/// PostgreSQL query transport used by the relational kernel.
pub trait PostgresTransport: Sync {
    /// Transport-specific error.
    type Error: StdError + Send + Sync + 'static;

    /// Reports whether a host error names a specific database constraint.
    /// Transports without structured diagnostics may conservatively inspect
    /// their bounded, parameter-free error text.
    fn violates_constraint(_error: &Self::Error, _constraint: &str) -> bool {
        false
    }

    /// Executes one parameterized PostgreSQL query and materializes its bounded
    /// result rows.
    fn query<'a>(
        &'a self,
        sql: &'static str,
        parameters: Vec<PgValue>,
    ) -> impl Future<Output = Result<Vec<PgRow>, Self::Error>> + Send + 'a;
}

/// Encrypted payload queued for asynchronous delivery.
pub struct SealedPayload {
    key_version: String,
    ciphertext: Vec<u8>,
}

impl SealedPayload {
    /// Constructs a non-empty versioned encrypted payload.
    ///
    /// # Errors
    ///
    /// Rejects an empty key version or ciphertext.
    pub fn new(
        key_version: impl Into<String>,
        ciphertext: impl Into<Vec<u8>>,
    ) -> Result<Self, KernelValidationError> {
        let key_version = key_version.into();
        let ciphertext = ciphertext.into();
        if key_version.is_empty() || key_version.len() > 128 || ciphertext.is_empty() {
            return Err(KernelValidationError::InvalidValue);
        }
        Ok(Self {
            key_version,
            ciphertext,
        })
    }

    /// Returns the non-secret key version needed to open this payload.
    #[must_use]
    pub fn key_version(&self) -> &str {
        &self.key_version
    }

    /// Returns the authenticated ciphertext for storage in PostgreSQL.
    #[must_use]
    pub fn ciphertext(&self) -> &[u8] {
        &self.ciphertext
    }
}

impl fmt::Debug for SealedPayload {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SealedPayload")
            .field("key_version", &self.key_version)
            .field("ciphertext", &"[REDACTED]")
            .finish()
    }
}

/// Bounded metadata common to externally retriable commands.
#[derive(Clone)]
pub struct CommandContext {
    idempotency_key: String,
    actor_key: String,
    request_hash: [u8; 32],
    request_id: RequestId,
    now_ms: u64,
    idempotency_expires_at_ms: u64,
}

impl fmt::Debug for CommandContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CommandContext")
            .field("idempotency_key", &"[REDACTED]")
            .field("actor_key", &"[REDACTED]")
            .field("request_hash", &"[REDACTED]")
            .field("request_id", &self.request_id)
            .field("now_ms", &self.now_ms)
            .field("idempotency_expires_at_ms", &self.idempotency_expires_at_ms)
            .finish()
    }
}

impl CommandContext {
    /// Constructs validated command metadata.
    ///
    /// # Errors
    ///
    /// Rejects malformed identifiers or a non-future idempotency expiry.
    pub fn new(
        idempotency_key: impl Into<String>,
        actor_key: impl Into<String>,
        request_hash: [u8; 32],
        request_id: RequestId,
        now_ms: u64,
        idempotency_expires_at_ms: u64,
    ) -> Result<Self, KernelValidationError> {
        let idempotency_key = idempotency_key.into();
        let actor_key = actor_key.into();
        if !bounded_token(&idempotency_key, 256)
            || !bounded_token(&actor_key, 256)
            || idempotency_expires_at_ms <= now_ms
        {
            return Err(KernelValidationError::InvalidValue);
        }
        Ok(Self {
            idempotency_key,
            actor_key,
            request_hash,
            request_id,
            now_ms,
            idempotency_expires_at_ms,
        })
    }
}

/// Prepared password-registration command.
pub struct RegisterPasswordCommand {
    /// Command metadata and idempotency binding.
    pub context: CommandContext,
    /// New UUIDv7 user identifier.
    pub user_id: Uuid,
    /// Canonical lower-case email used for uniqueness.
    pub normalized_email: String,
    /// User-facing primary email.
    pub primary_email: String,
    /// Argon2id password hash.
    pub password_hash: String,
    /// Hash of the opaque verification token.
    pub verification_token_hash: [u8; 32],
    /// Safe post-verification redirect URI.
    pub redirect_uri: String,
    /// Verification token expiry.
    pub verification_expires_at_ms: u64,
    /// New outbox identifier.
    pub outbox_id: Uuid,
    /// Stable provider deduplication key.
    pub outbox_deduplication_key: String,
    /// Encrypted verification message payload.
    pub outbox_payload: SealedPayload,
    /// New audit record identifier.
    pub audit_id: Uuid,
    /// Non-secret structured audit metadata.
    pub audit_metadata: Value,
}

impl fmt::Debug for RegisterPasswordCommand {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RegisterPasswordCommand")
            .field("context", &self.context)
            .field("user_id", &self.user_id)
            .field("normalized_email", &"[REDACTED]")
            .field("primary_email", &"[REDACTED]")
            .field("password_hash", &"[REDACTED]")
            .field("verification_token_hash", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field(
                "verification_expires_at_ms",
                &self.verification_expires_at_ms,
            )
            .field("outbox_id", &self.outbox_id)
            .field("outbox_deduplication_key", &self.outbox_deduplication_key)
            .field("outbox_payload", &self.outbox_payload)
            .field("audit_id", &self.audit_id)
            .field("audit_metadata", &"[REDACTED]")
            .finish()
    }
}

impl RegisterPasswordCommand {
    fn validate(&self) -> Result<(), KernelValidationError> {
        if !valid_email_pair(&self.normalized_email, &self.primary_email)
            || self.password_hash.is_empty()
            || self.password_hash.len() > 2_048
            || !safe_redirect(&self.redirect_uri)
            || self.verification_expires_at_ms <= self.context.now_ms
            || !bounded_token(&self.outbox_deduplication_key, 256)
            || !self.audit_metadata.is_object()
        {
            return Err(KernelValidationError::InvalidValue);
        }
        Ok(())
    }

    fn parameters(self) -> Vec<PgValue> {
        vec![
            PgValue::Text(self.context.idempotency_key),
            PgValue::Text(self.context.actor_key),
            PgValue::Bytes(self.context.request_hash.to_vec()),
            PgValue::Text(self.user_id.to_string()),
            PgValue::Text(self.normalized_email),
            PgValue::Text(self.primary_email),
            PgValue::Text(self.password_hash),
            PgValue::Bytes(self.verification_token_hash.to_vec()),
            PgValue::Text(self.redirect_uri),
            PgValue::I64(u64_to_i64(self.verification_expires_at_ms)),
            PgValue::Text(self.outbox_id.to_string()),
            PgValue::Text(self.outbox_deduplication_key),
            PgValue::Text(self.outbox_payload.key_version),
            PgValue::Bytes(self.outbox_payload.ciphertext),
            PgValue::Text(self.audit_id.to_string()),
            PgValue::Text(self.context.request_id.into_string()),
            PgValue::Json(self.audit_metadata),
            PgValue::I64(u64_to_i64(self.context.now_ms)),
            PgValue::I64(u64_to_i64(self.context.idempotency_expires_at_ms)),
        ]
    }
}

/// Successful registration persistence result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RegistrationReceipt {
    /// Stable user identifier.
    pub user_id: UserId,
    /// Whether a matching idempotent result was replayed.
    pub replayed: bool,
}

/// Authoritative session identity plus the verified request context built from
/// the same hot-path query.
#[derive(Clone, Debug)]
pub struct VerifiedSession {
    context: VerifiedRequestContext,
    primary_email: String,
    #[cfg(all(feature = "jwt", feature = "password"))]
    authorization_fingerprint: AuthorizationFingerprint,
}

impl VerifiedSession {
    /// Returns the verified request context.
    #[must_use]
    pub const fn context(&self) -> &VerifiedRequestContext {
        &self.context
    }

    /// Returns the account primary email loaded with the session.
    #[must_use]
    pub fn primary_email(&self) -> &str {
        &self.primary_email
    }

    #[cfg(all(feature = "jwt", feature = "password"))]
    pub(crate) const fn authorization_fingerprint(&self) -> &AuthorizationFingerprint {
        &self.authorization_fingerprint
    }

    /// Consumes the envelope and returns its verified request context.
    #[must_use]
    pub fn into_context(self) -> VerifiedRequestContext {
        self.context
    }
}

/// Opaque revision tuple proving which relational authorization snapshot was
/// loaded. It is deliberately private to the authentication kernel so callers
/// can reuse a snapshot but cannot manufacture a cache hit.
#[derive(Clone, Debug, Eq, PartialEq)]
#[cfg(all(feature = "jwt", feature = "password"))]
pub(crate) struct AuthorizationFingerprint {
    user_id: String,
    session_id: String,
    organization_id: Option<String>,
    assurance: String,
    expires_at_ms: i64,
    session_revision: i64,
    user_security_revision: i64,
    organization_authorization_revision: Option<i64>,
    role_id: Option<String>,
    policy_revision: Option<String>,
    system_administrator: bool,
}

/// Relational authentication store backed by one PostgreSQL transport.
#[derive(Clone, Debug)]
pub struct PostgresAuthStore<T> {
    transport: T,
}

impl<T> PostgresAuthStore<T> {
    /// Wraps a PostgreSQL query transport.
    #[must_use]
    pub const fn new(transport: T) -> Self {
        Self { transport }
    }

    /// Returns the underlying transport.
    #[must_use]
    pub const fn transport(&self) -> &T {
        &self.transport
    }
}

impl<T> PostgresAuthStore<T>
where
    T: PostgresTransport,
{
    /// Atomically registers a password account, verification token, encrypted
    /// mail intent, audit record, and idempotency result.
    ///
    /// # Errors
    ///
    /// Returns validation, duplicate-email, idempotency-conflict, row-decoding,
    /// or transport errors. No partial state is committed.
    pub async fn register_password(
        &self,
        command: RegisterPasswordCommand,
    ) -> Result<RegistrationReceipt, PostgresStoreError<T::Error>> {
        command.validate()?;
        let idempotency_key = command.context.idempotency_key.clone();
        let actor_key = command.context.actor_key.clone();
        let request_hash = command.context.request_hash;
        let rows = self
            .transport
            .query(REGISTER_PASSWORD_SQL, command.parameters())
            .await
            .map_err(PostgresStoreError::Transport)?;
        match registration_outcome(&rows)? {
            RegistrationOutcome::Receipt(receipt) => Ok(receipt),
            RegistrationOutcome::EmailConflict => self
                .registration_replay(&idempotency_key, &actor_key, request_hash)
                .await?
                .ok_or(PostgresStoreError::EmailAlreadyExists),
            RegistrationOutcome::IdempotencyConflict => {
                Err(PostgresStoreError::IdempotencyConflict)
            }
        }
    }

    async fn registration_replay(
        &self,
        idempotency_key: &str,
        actor_key: &str,
        request_hash: [u8; 32],
    ) -> Result<Option<RegistrationReceipt>, PostgresStoreError<T::Error>> {
        let rows = self
            .transport
            .query(
                REGISTRATION_REPLAY_SQL,
                vec![
                    PgValue::Text(idempotency_key.to_owned()),
                    PgValue::Text(actor_key.to_owned()),
                    PgValue::Bytes(request_hash.to_vec()),
                ],
            )
            .await
            .map_err(PostgresStoreError::Transport)?;
        let Some(row) = rows.first() else {
            return Ok(None);
        };
        match row.required_text("outcome")? {
            "replayed" => Ok(Some(receipt_from_row(row, true)?)),
            "idempotency_conflict" => Err(PostgresStoreError::IdempotencyConflict),
            _ => Err(PostgresStoreError::UnexpectedOutcome),
        }
    }

    /// Loads and verifies all request identity and authorization facts in one
    /// authoritative query.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError::Unauthenticated`] for an absent, expired,
    /// revoked, disabled, stale-revision, or invalid-organization session.
    pub async fn load_request_context(
        &self,
        session_id: &SessionId,
        request_id: RequestId,
        now_unix_seconds: u64,
    ) -> Result<VerifiedRequestContext, PostgresStoreError<T::Error>> {
        self.load_verified_session(session_id, request_id, now_unix_seconds)
            .await
            .map(VerifiedSession::into_context)
    }

    /// Loads account display identity and all authorization facts in the same
    /// authoritative query used by trusted ingress.
    ///
    /// # Errors
    ///
    /// Returns [`PostgresStoreError::Unauthenticated`] for an unavailable
    /// session and fails closed on malformed stored identity data.
    pub async fn load_verified_session(
        &self,
        session_id: &SessionId,
        request_id: RequestId,
        now_unix_seconds: u64,
    ) -> Result<VerifiedSession, PostgresStoreError<T::Error>> {
        self.load_verified_session_with_signing_key(session_id, request_id, now_unix_seconds, "")
            .await
    }

    /// Loads an authoritative session only when the token signing key remains
    /// active or retired in relational lifecycle state.
    ///
    /// This keeps immediate key revocation on the same bounded query as user,
    /// session, organization, role, permission, and policy validation.
    #[cfg(all(feature = "jwt", feature = "password"))]
    pub(crate) async fn load_verified_session_for_token(
        &self,
        session_id: &SessionId,
        request_id: RequestId,
        now_unix_seconds: u64,
        signing_key_id: &str,
    ) -> Result<VerifiedSession, PostgresStoreError<T::Error>> {
        if !valid_signing_key_id(signing_key_id) {
            return Err(PostgresStoreError::Unauthenticated);
        }
        self.load_verified_session_with_signing_key(
            session_id,
            request_id,
            now_unix_seconds,
            signing_key_id,
        )
        .await
    }

    /// Loads only the revision tuple required to prove a previously loaded
    /// authorization snapshot is still current. Session, account,
    /// organization, membership, policy, administrator, and signing-key
    /// revocations all remain authoritative on every cache hit.
    #[cfg(all(feature = "jwt", feature = "password"))]
    pub(crate) async fn load_authorization_fingerprint_for_token(
        &self,
        session_id: &SessionId,
        now_unix_seconds: u64,
        signing_key_id: &str,
    ) -> Result<AuthorizationFingerprint, PostgresStoreError<T::Error>> {
        if !valid_signing_key_id(signing_key_id) {
            return Err(PostgresStoreError::Unauthenticated);
        }
        let rows = self
            .transport
            .query(
                LOAD_REQUEST_FINGERPRINT_SQL,
                vec![
                    PgValue::Text(session_id.as_str().to_owned()),
                    PgValue::I64(u64_to_i64(now_unix_seconds.saturating_mul(1_000))),
                    PgValue::Text(signing_key_id.to_owned()),
                ],
            )
            .await
            .map_err(PostgresStoreError::Transport)?;
        let row = rows.first().ok_or(PostgresStoreError::Unauthenticated)?;
        authorization_fingerprint(row).map_err(Into::into)
    }

    async fn load_verified_session_with_signing_key(
        &self,
        session_id: &SessionId,
        request_id: RequestId,
        now_unix_seconds: u64,
        signing_key_id: &str,
    ) -> Result<VerifiedSession, PostgresStoreError<T::Error>> {
        let now_ms = now_unix_seconds.saturating_mul(1_000);
        let rows = self
            .transport
            .query(
                LOAD_REQUEST_CONTEXT_SQL,
                vec![
                    PgValue::Text(session_id.as_str().to_owned()),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::Text(signing_key_id.to_owned()),
                ],
            )
            .await
            .map_err(PostgresStoreError::Transport)?;
        let row = rows.first().ok_or(PostgresStoreError::Unauthenticated)?;
        verified_session(row, request_id).map_err(Into::into)
    }
}

enum RegistrationOutcome {
    Receipt(RegistrationReceipt),
    EmailConflict,
    IdempotencyConflict,
}

fn registration_outcome<E>(rows: &[PgRow]) -> Result<RegistrationOutcome, PostgresStoreError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let row = rows.first().ok_or(PostgresStoreError::UnexpectedOutcome)?;
    match row.required_text("outcome")? {
        "created" => Ok(RegistrationOutcome::Receipt(receipt_from_row(row, false)?)),
        "replayed" => Ok(RegistrationOutcome::Receipt(receipt_from_row(row, true)?)),
        "email_conflict" => Ok(RegistrationOutcome::EmailConflict),
        "idempotency_conflict" => Ok(RegistrationOutcome::IdempotencyConflict),
        _ => Err(PostgresStoreError::UnexpectedOutcome),
    }
}

fn receipt_from_row<E>(
    row: &PgRow,
    replayed: bool,
) -> Result<RegistrationReceipt, PostgresStoreError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    Ok(RegistrationReceipt {
        user_id: UserId::new(row.required_text("user_id")?)?,
        replayed,
    })
}

fn verified_session(
    row: &PgRow,
    request_id: RequestId,
) -> Result<VerifiedSession, ContextLoadError> {
    #[cfg(all(feature = "jwt", feature = "password"))]
    let authorization_fingerprint = authorization_fingerprint(row)?;
    let user_id = UserId::new(row.required_text("user_id")?)?;
    let primary_email = row.required_text("primary_email")?.to_owned();
    if primary_email.len() > 320 || primary_email.chars().any(char::is_control) {
        return Err(ContextLoadError::InvalidEmail);
    }
    let organization_id = row
        .text("organization_id")?
        .map(OrganizationId::new)
        .transpose()?;
    let session_id = SessionId::new(row.required_text("session_id")?)?;
    let assurance = match row.required_text("assurance")? {
        "aal1" => AuthenticationAssurance::Aal1,
        "aal2" | "aal3" => AuthenticationAssurance::Aal2,
        _ => return Err(ContextLoadError::InvalidAssurance),
    };
    let expires_at_ms = row.required_i64("expires_at_ms")?;
    let created_at_ms = row.required_i64("created_at_ms")?;
    if expires_at_ms <= 0 || created_at_ms < 0 || created_at_ms >= expires_at_ms {
        return Err(ContextLoadError::InvalidTimestamp);
    }
    let policy_revision = row
        .text("policy_revision")?
        .map(PolicyRevision::new)
        .transpose()?;
    let role_ids = row
        .text("role_id")?
        .map(RoleId::new)
        .transpose()?
        .into_iter();
    let permissions = row
        .json("permissions")?
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .map(|value| {
            value
                .as_str()
                .map(str::to_owned)
                .ok_or(ContextLoadError::InvalidPermissions)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let principal = Principal::new(
        user_id,
        "wasi-auth",
        row.bool("system_administrator")?.unwrap_or(false),
    )?;
    let auth = VerifiedAuthContext::from_validated(ValidatedContextParts {
        principal,
        organization_id,
        session_id,
        request_id,
        assurance,
        issued_at_unix_seconds: (created_at_ms as u64) / 1_000,
        expires_at_unix_seconds: (expires_at_ms as u64) / 1_000,
        decision_id: None,
        policy_revision: policy_revision.clone(),
    })?;
    let authorization = AuthorizationSnapshot::new(permissions, role_ids, policy_revision, None)?;
    Ok(VerifiedSession {
        context: VerifiedRequestContext::from_verified(auth, authorization),
        primary_email,
        #[cfg(all(feature = "jwt", feature = "password"))]
        authorization_fingerprint,
    })
}

#[cfg(all(feature = "jwt", feature = "password"))]
fn authorization_fingerprint(row: &PgRow) -> Result<AuthorizationFingerprint, ContextLoadError> {
    let user_id = UserId::new(row.required_text("user_id")?)?.to_string();
    let session_id = SessionId::new(row.required_text("session_id")?)?.to_string();
    let organization_id = row
        .text("organization_id")?
        .map(OrganizationId::new)
        .transpose()?
        .map(|value| value.to_string());
    let assurance = match row.required_text("assurance")? {
        "aal1" => "aal1".to_owned(),
        "aal2" | "aal3" => "aal2".to_owned(),
        _ => return Err(ContextLoadError::InvalidAssurance),
    };
    let expires_at_ms = row.required_i64("expires_at_ms")?;
    let session_revision = row.required_i64("session_revision")?;
    let user_security_revision = row.required_i64("user_security_revision")?;
    let organization_authorization_revision = row.i64("organization_authorization_revision")?;
    let role_id = row
        .text("role_id")?
        .map(RoleId::new)
        .transpose()?
        .map(|value| value.to_string());
    let policy_revision = row
        .text("policy_revision")?
        .map(PolicyRevision::new)
        .transpose()?
        .map(|value| value.to_string());
    if expires_at_ms <= 0
        || session_revision <= 0
        || user_security_revision <= 0
        || organization_authorization_revision.is_some_and(|revision| revision <= 0)
        || organization_id.is_some()
            != (organization_authorization_revision.is_some() && role_id.is_some())
    {
        return Err(ContextLoadError::InvalidRevision);
    }
    Ok(AuthorizationFingerprint {
        user_id,
        session_id,
        organization_id,
        assurance,
        expires_at_ms,
        session_revision,
        user_security_revision,
        organization_authorization_revision,
        role_id,
        policy_revision,
        system_administrator: row.bool("system_administrator")?.unwrap_or(false),
    })
}

/// Relational-kernel input validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum KernelValidationError {
    /// One or more command values violated a bound or invariant.
    #[error("relational auth command contains an invalid value")]
    InvalidValue,
}

/// PostgreSQL row decoding failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RowDecodeError {
    /// A required column was absent or null.
    #[error("PostgreSQL row is missing required column {0}")]
    Missing(&'static str),
    /// A column had an unexpected wire type.
    #[error("PostgreSQL row column {0} has an unexpected type")]
    WrongType(&'static str),
}

#[derive(Debug, Error)]
enum ContextLoadError {
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    #[error(transparent)]
    Context(#[from] crate::context::ContextError),
    #[error("stored assurance is invalid")]
    InvalidAssurance,
    #[error("stored timestamp is invalid")]
    InvalidTimestamp,
    #[error("stored permissions are invalid")]
    InvalidPermissions,
    #[error("stored primary email is invalid")]
    InvalidEmail,
    #[error("stored authorization revision is invalid")]
    #[cfg(all(feature = "jwt", feature = "password"))]
    InvalidRevision,
}

/// PostgreSQL relational-store failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PostgresStoreError<E: StdError + Send + Sync + 'static> {
    /// PostgreSQL transport failed.
    #[error("PostgreSQL auth transport failed: {0}")]
    Transport(#[source] E),
    /// Command validation failed before storage was called.
    #[error(transparent)]
    Validation(#[from] KernelValidationError),
    /// Stored row decoding failed closed.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// Bounded context construction rejected stored data.
    #[error("stored authentication context is invalid")]
    Context,
    /// The normalized email already belongs to an account.
    #[error("an account already exists for this email")]
    EmailAlreadyExists,
    /// An idempotency key was reused for a different command.
    #[error("idempotency key conflicts with a different request")]
    IdempotencyConflict,
    /// No active authoritative session matched the credential.
    #[error("request is unauthenticated")]
    Unauthenticated,
    /// PostgreSQL returned an outcome outside the command contract.
    #[error("PostgreSQL auth command returned an unexpected outcome")]
    UnexpectedOutcome,
}

impl<E> From<crate::context::ContextError> for PostgresStoreError<E>
where
    E: StdError + Send + Sync + 'static,
{
    fn from(_: crate::context::ContextError) -> Self {
        Self::Context
    }
}

impl<E> From<ContextLoadError> for PostgresStoreError<E>
where
    E: StdError + Send + Sync + 'static,
{
    fn from(error: ContextLoadError) -> Self {
        match error {
            ContextLoadError::Row(error) => Self::Row(error),
            ContextLoadError::Context(_)
            | ContextLoadError::InvalidAssurance
            | ContextLoadError::InvalidTimestamp
            | ContextLoadError::InvalidPermissions
            | ContextLoadError::InvalidEmail => Self::Context,
            #[cfg(all(feature = "jwt", feature = "password"))]
            ContextLoadError::InvalidRevision => Self::Context,
        }
    }
}

#[cfg(all(feature = "jwt", feature = "password"))]
fn valid_signing_key_id(value: &str) -> bool {
    !value.is_empty() && value.len() <= 128 && !value.chars().any(char::is_control)
}

fn bounded_token(value: &str, maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.chars().any(|character| character.is_control())
}

fn valid_email_pair(normalized: &str, primary: &str) -> bool {
    normalized == normalized.trim()
        && normalized == normalized.to_ascii_lowercase()
        && normalized.len() <= 320
        && primary.len() <= 320
        && normalized.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && domain.contains('.')
        })
}

fn safe_redirect(value: &str) -> bool {
    value.starts_with('/') && !value.starts_with("//") && !value.chars().any(char::is_control)
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use std::{collections::VecDeque, sync::Mutex};

    use futures::executor::block_on;

    use super::*;

    #[derive(Debug, Error)]
    #[error("fixture transport failed")]
    struct FixtureError;

    #[derive(Default)]
    struct FixtureTransport {
        responses: Mutex<VecDeque<Vec<PgRow>>>,
        calls: Mutex<Vec<(&'static str, Vec<PgValue>)>>,
    }

    impl FixtureTransport {
        fn with_response(response: Vec<PgRow>) -> Self {
            Self::with_responses([response])
        }

        fn with_responses(responses: impl IntoIterator<Item = Vec<PgRow>>) -> Self {
            Self {
                responses: Mutex::new(responses.into_iter().collect()),
                calls: Mutex::default(),
            }
        }
    }

    impl PostgresTransport for FixtureTransport {
        type Error = FixtureError;

        async fn query(
            &self,
            sql: &'static str,
            parameters: Vec<PgValue>,
        ) -> Result<Vec<PgRow>, Self::Error> {
            self.calls
                .lock()
                .map_err(|_| FixtureError)?
                .push((sql, parameters));
            self.responses
                .lock()
                .map_err(|_| FixtureError)?
                .pop_front()
                .ok_or(FixtureError)
        }
    }

    fn registration_command() -> RegisterPasswordCommand {
        RegisterPasswordCommand {
            context: CommandContext::new(
                "registration-one",
                "anonymous:127.0.0.1",
                [7; 32],
                RequestId::new("request-one").expect("valid request"),
                1_000,
                61_000,
            )
            .expect("valid context"),
            user_id: Uuid::now_v7(),
            normalized_email: "person@example.com".to_owned(),
            primary_email: "person@example.com".to_owned(),
            password_hash: "$argon2id$v=19$m=65536,t=3,p=1$fixture".to_owned(),
            verification_token_hash: [8; 32],
            redirect_uri: "/verify-email".to_owned(),
            verification_expires_at_ms: 901_000,
            outbox_id: Uuid::now_v7(),
            outbox_deduplication_key: "verify:user-one:v1".to_owned(),
            outbox_payload: SealedPayload::new("key-v1", [9; 48]).expect("sealed"),
            audit_id: Uuid::now_v7(),
            audit_metadata: serde_json::json!({"source":"test"}),
        }
    }

    #[test]
    fn registration_uses_one_parameterized_statement_and_redacts_debug() {
        let command = registration_command();
        let user_id = command.user_id.to_string();
        let debug = format!("{command:?}");
        let transport = FixtureTransport::with_response(vec![PgRow::new([
            ("outcome".to_owned(), PgValue::Text("created".to_owned())),
            ("user_id".to_owned(), PgValue::Text(user_id.clone())),
        ])]);
        let store = PostgresAuthStore::new(transport);

        let receipt = block_on(store.register_password(command)).expect("registration succeeds");

        assert_eq!(receipt.user_id.as_str(), user_id);
        assert!(!receipt.replayed);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("person@example.com"));
        assert_eq!(store.transport.calls.lock().expect("calls").len(), 1);
        assert!(REGISTER_PASSWORD_SQL.contains("WITH existing_idempotency"));
        assert!(!REGISTER_PASSWORD_SQL.contains("?1"));
    }

    #[test]
    fn registration_replays_matching_idempotency_result() {
        let command = registration_command();
        let user_id = command.user_id.to_string();
        let transport = FixtureTransport::with_response(vec![PgRow::new([
            ("outcome".to_owned(), PgValue::Text("replayed".to_owned())),
            ("user_id".to_owned(), PgValue::Text(user_id.clone())),
        ])]);
        let store = PostgresAuthStore::new(transport);

        let receipt = block_on(store.register_password(command)).expect("replayed");

        assert_eq!(receipt.user_id.as_str(), user_id);
        assert!(receipt.replayed);
    }

    #[cfg(all(feature = "jwt", feature = "password"))]
    #[test]
    fn token_context_load_is_one_query_with_authoritative_key_lifecycle() {
        let user_id = Uuid::now_v7().to_string();
        let session_id = Uuid::now_v7().to_string();
        let row = PgRow::new([
            ("user_id".to_owned(), PgValue::Text(user_id.clone())),
            (
                "primary_email".to_owned(),
                PgValue::Text("verified@example.com".to_owned()),
            ),
            ("session_id".to_owned(), PgValue::Text(session_id.clone())),
            ("organization_id".to_owned(), PgValue::Null),
            ("assurance".to_owned(), PgValue::Text("aal1".to_owned())),
            ("created_at_ms".to_owned(), PgValue::I64(1_000)),
            ("expires_at_ms".to_owned(), PgValue::I64(61_000)),
            ("session_revision".to_owned(), PgValue::I64(1)),
            ("user_security_revision".to_owned(), PgValue::I64(1)),
            (
                "organization_authorization_revision".to_owned(),
                PgValue::Null,
            ),
            ("role_id".to_owned(), PgValue::Null),
            (
                "permissions".to_owned(),
                PgValue::Json(serde_json::json!([])),
            ),
            ("policy_revision".to_owned(), PgValue::Null),
            ("system_administrator".to_owned(), PgValue::Bool(false)),
        ]);
        let transport = FixtureTransport::with_responses([vec![row.clone()], vec![row]]);
        let store = PostgresAuthStore::new(transport);

        let verified = block_on(store.load_verified_session_for_token(
            &SessionId::new(session_id.clone()).expect("valid session id"),
            RequestId::new("token-context-request").expect("valid request id"),
            2,
            "signing-key-v1",
        ))
        .expect("verified token context");

        assert_eq!(
            verified.context().auth().principal().user_id().as_str(),
            user_id
        );
        let calls = store.transport.calls.lock().expect("calls");
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, LOAD_REQUEST_CONTEXT_SQL);
        assert_eq!(calls[0].1.len(), 3);
        assert_eq!(calls[0].1[2], PgValue::Text("signing-key-v1".to_owned()));
        assert!(LOAD_REQUEST_CONTEXT_SQL.contains("signing_key.status IN ('active', 'retired')"));
        drop(calls);

        let fingerprint = block_on(store.load_authorization_fingerprint_for_token(
            &SessionId::new(session_id).expect("valid session id"),
            2,
            "signing-key-v1",
        ))
        .expect("authoritative fingerprint");
        assert_eq!(fingerprint, *verified.authorization_fingerprint());
        let calls = store.transport.calls.lock().expect("calls");
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[1].0, LOAD_REQUEST_FINGERPRINT_SQL);
        assert!(!LOAD_REQUEST_FINGERPRINT_SQL.contains("auth_role_permissions"));
    }

    #[test]
    fn command_context_rejects_non_future_expiry() {
        let result = CommandContext::new(
            "key",
            "actor",
            [0; 32],
            RequestId::new("request").expect("request"),
            100,
            100,
        );

        assert!(matches!(result, Err(KernelValidationError::InvalidValue)));
    }
}
