//! Complete authentication workflows backed by the PostgreSQL command kernel.

use std::{error::Error as StdError, fmt};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde_json::json;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use super::{
    CommandContext, PgValue, PostgresAuthStore, PostgresStoreError, PostgresTransport,
    RegisterPasswordCommand, RegistrationReceipt, RowDecodeError, SealedPayload,
};
use crate::{
    authentication::{Clock, RandomSource},
    context::{RequestId, SessionId, UserId},
};

const PASSWORD_HASH_BYTES: usize = 32;
const PASSWORD_SALT_BYTES: usize = 16;
const VERIFICATION_TOKEN_BYTES: usize = 32;
const OUTBOX_NONCE_BYTES: usize = 12;
const UUID_RANDOM_BYTES: usize = 10;
const EMAIL_VERIFICATION_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
const IDEMPOTENCY_TTL_MS: u64 = 24 * 60 * 60 * 1_000;
// This value is frozen because changing authenticated data would make already
// queued mail payloads unreadable.
const MAIL_OUTBOX_AAD_V1: &[u8] = b"wasi-auth:email-verification:v1";
const LOAD_PASSWORD_LOGIN_SQL: &str = include_str!("load_password_login.sql");
const ISSUE_PASSWORD_SESSION_SQL: &str = include_str!("issue_password_session.sql");
const LOAD_PASSWORD_BY_USER_SQL: &str = include_str!("load_password_by_user.sql");
const CHANGE_PASSWORD_SQL: &str = include_str!("change_password.sql");
const VERIFY_EMAIL_SQL: &str = include_str!("verify_email.sql");
const RESEND_EMAIL_VERIFICATION_SQL: &str = include_str!("resend_email_verification.sql");
const START_PASSWORD_RESET_SQL: &str = include_str!("start_password_reset.sql");
const COMPLETE_PASSWORD_RESET_SQL: &str = include_str!("complete_password_reset.sql");
const DEFAULT_SESSION_TTL_MS: u64 = 60 * 60 * 1_000;
const PASSWORD_RESET_TTL_MS: u64 = 15 * 60 * 1_000;
const DUMMY_PASSWORD_HASH: &str =
    "argon2id$m=19456,t=2,p=1$AAAAAAAAAAAAAAAAAAAAAA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// Validated Argon2id policy used for password registration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Argon2Policy {
    memory_kib: u32,
    iterations: u32,
    parallelism: u32,
}

impl Argon2Policy {
    /// Constructs a bounded Argon2id policy.
    ///
    /// # Errors
    ///
    /// Rejects unsupported or unreasonably weak/large parameters.
    pub fn new(
        memory_kib: u32,
        iterations: u32,
        parallelism: u32,
    ) -> Result<Self, PasswordRegistrationError<std::convert::Infallible>> {
        if !(19_456..=1_048_576).contains(&memory_kib)
            || !(2..=10).contains(&iterations)
            || !(1..=16).contains(&parallelism)
        {
            return Err(PasswordRegistrationError::InvalidConfiguration);
        }
        Params::new(
            memory_kib,
            iterations,
            parallelism,
            Some(PASSWORD_HASH_BYTES),
        )
        .map_err(|_| PasswordRegistrationError::InvalidConfiguration)?;
        Ok(Self {
            memory_kib,
            iterations,
            parallelism,
        })
    }

    fn params(self) -> Result<Params, PasswordCryptoError> {
        Params::new(
            self.memory_kib,
            self.iterations,
            self.parallelism,
            Some(PASSWORD_HASH_BYTES),
        )
        .map_err(|_| PasswordCryptoError)
    }
}

impl Default for Argon2Policy {
    fn default() -> Self {
        Self {
            memory_kib: 19_456,
            iterations: 2,
            parallelism: 1,
        }
    }
}

/// AES-256-GCM key used only to seal durable outbox payloads.
pub struct OutboxSealingKey {
    key_version: String,
    key: [u8; 32],
}

impl OutboxSealingKey {
    /// Constructs a versioned outbox encryption key.
    ///
    /// # Errors
    ///
    /// Rejects an empty, oversized, or control-character-containing version.
    pub fn new(
        key_version: impl Into<String>,
        key: [u8; 32],
    ) -> Result<Self, PasswordRegistrationError<std::convert::Infallible>> {
        let key_version = key_version.into();
        if key_version.is_empty()
            || key_version.len() > 128
            || key_version.chars().any(char::is_control)
        {
            return Err(PasswordRegistrationError::InvalidConfiguration);
        }
        Ok(Self { key_version, key })
    }

    pub(crate) fn seal(
        &self,
        nonce: [u8; OUTBOX_NONCE_BYTES],
        plaintext: &[u8],
    ) -> Result<SealedPayload, PasswordCryptoError> {
        self.seal_with_aad(nonce, plaintext, MAIL_OUTBOX_AAD_V1)
    }

    fn seal_with_aad(
        &self,
        nonce: [u8; OUTBOX_NONCE_BYTES],
        plaintext: &[u8],
        aad: &[u8],
    ) -> Result<SealedPayload, PasswordCryptoError> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| PasswordCryptoError)?;
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad,
                },
            )
            .map_err(|_| PasswordCryptoError)?;
        let mut sealed = Vec::with_capacity(nonce.len() + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        SealedPayload::new(self.key_version.clone(), sealed).map_err(|_| PasswordCryptoError)
    }

    pub(crate) fn open(
        &self,
        key_version: &str,
        sealed: &[u8],
    ) -> Result<Vec<u8>, PasswordCryptoError> {
        self.open_with_aad(key_version, sealed, MAIL_OUTBOX_AAD_V1)
    }

    fn open_with_aad(
        &self,
        key_version: &str,
        sealed: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, PasswordCryptoError> {
        if key_version != self.key_version || sealed.len() <= OUTBOX_NONCE_BYTES {
            return Err(PasswordCryptoError);
        }
        let (nonce, ciphertext) = sealed.split_at(OUTBOX_NONCE_BYTES);
        let nonce: [u8; OUTBOX_NONCE_BYTES] = nonce.try_into().map_err(|_| PasswordCryptoError)?;
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| PasswordCryptoError)?;
        cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad,
                },
            )
            .map_err(|_| PasswordCryptoError)
    }
}

impl fmt::Debug for OutboxSealingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OutboxSealingKey")
            .field("key_version", &self.key_version)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for OutboxSealingKey {
    fn drop(&mut self) {
        self.key.fill(0);
    }
}

/// Browser/API password-registration input.
pub struct PasswordRegistrationRequest {
    idempotency_key: String,
    actor_key: String,
    request_id: RequestId,
    email: String,
    password: String,
    redirect_uri: String,
}

/// Generic email-verification resend input.
pub struct EmailVerificationResendRequest {
    email: String,
    request_id: RequestId,
    redirect_uri: String,
}

impl EmailVerificationResendRequest {
    /// Constructs a resend request. The workflow always returns a generic
    /// accepted response so account state cannot be enumerated.
    #[must_use]
    pub fn new(
        email: impl Into<String>,
        request_id: RequestId,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            email: email.into(),
            request_id,
            redirect_uri: redirect_uri.into(),
        }
    }
}

impl fmt::Debug for EmailVerificationResendRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailVerificationResendRequest")
            .field("email", &"[REDACTED]")
            .field("request_id", &self.request_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl PasswordRegistrationRequest {
    /// Constructs a registration request. Full validation occurs before any
    /// cryptographic or persistence operation.
    #[must_use]
    pub fn new(
        idempotency_key: impl Into<String>,
        actor_key: impl Into<String>,
        request_id: RequestId,
        email: impl Into<String>,
        password: impl Into<String>,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            idempotency_key: idempotency_key.into(),
            actor_key: actor_key.into(),
            request_id,
            email: email.into(),
            password: password.into(),
            redirect_uri: redirect_uri.into(),
        }
    }
}

impl fmt::Debug for PasswordRegistrationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordRegistrationRequest")
            .field("idempotency_key", &"[REDACTED]")
            .field("actor_key", &"[REDACTED]")
            .field("request_id", &self.request_id)
            .field("email", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl Drop for PasswordRegistrationRequest {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Browser/API password-login input.
pub struct PasswordLoginRequest {
    email: String,
    password: String,
    request_id: RequestId,
    redirect_uri: String,
}

impl PasswordLoginRequest {
    /// Constructs a password-login request.
    #[must_use]
    pub fn new(
        email: impl Into<String>,
        password: impl Into<String>,
        request_id: RequestId,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            email: email.into(),
            password: password.into(),
            request_id,
            redirect_uri: redirect_uri.into(),
        }
    }
}

impl fmt::Debug for PasswordLoginRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordLoginRequest")
            .field("email", &"[REDACTED]")
            .field("password", &"[REDACTED]")
            .field("request_id", &self.request_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl Drop for PasswordLoginRequest {
    fn drop(&mut self) {
        self.password.zeroize();
    }
}

/// Step-up protected password-change input.
pub struct PasswordChangeRequest {
    user_id: UserId,
    session_id: SessionId,
    current_password: String,
    new_password: String,
    request_id: RequestId,
}

impl PasswordChangeRequest {
    /// Constructs a password-change request from verified identity.
    #[must_use]
    pub fn new(
        user_id: UserId,
        session_id: SessionId,
        current_password: impl Into<String>,
        new_password: impl Into<String>,
        request_id: RequestId,
    ) -> Self {
        Self {
            user_id,
            session_id,
            current_password: current_password.into(),
            new_password: new_password.into(),
            request_id,
        }
    }
}

impl fmt::Debug for PasswordChangeRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordChangeRequest")
            .field("user_id", &self.user_id)
            .field("session_id", &self.session_id)
            .field("current_password", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .field("request_id", &self.request_id)
            .finish()
    }
}

impl Drop for PasswordChangeRequest {
    fn drop(&mut self) {
        self.current_password.zeroize();
        self.new_password.zeroize();
    }
}

/// Opaque email-verification completion input.
pub struct EmailVerificationRequest {
    token: String,
    request_id: RequestId,
    redirect_uri: String,
}

impl EmailVerificationRequest {
    /// Constructs an email-verification request.
    #[must_use]
    pub fn new(
        token: impl Into<String>,
        request_id: RequestId,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            token: token.into(),
            request_id,
            redirect_uri: redirect_uri.into(),
        }
    }
}

impl fmt::Debug for EmailVerificationRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("EmailVerificationRequest")
            .field("token", &"[REDACTED]")
            .field("request_id", &self.request_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl Drop for EmailVerificationRequest {
    fn drop(&mut self) {
        self.token.zeroize();
    }
}

/// Privacy-preserving password-reset start input.
#[derive(Clone)]
pub struct PasswordResetStartRequest {
    /// Account email. The result never reveals whether it exists.
    pub email: String,
    /// Validated local redirect after completion.
    pub redirect_uri: String,
    /// Request correlation identifier.
    pub request_id: RequestId,
}

impl PasswordResetStartRequest {
    /// Constructs a reset-start request.
    #[must_use]
    pub fn new(
        email: impl Into<String>,
        redirect_uri: impl Into<String>,
        request_id: RequestId,
    ) -> Self {
        Self {
            email: email.into(),
            redirect_uri: redirect_uri.into(),
            request_id,
        }
    }
}

impl fmt::Debug for PasswordResetStartRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordResetStartRequest")
            .field("email", &"[REDACTED]")
            .field("redirect_uri", &self.redirect_uri)
            .field("request_id", &self.request_id)
            .finish()
    }
}

/// Password-reset completion input containing one-time secrets.
pub struct PasswordResetCompleteRequest {
    token: String,
    new_password: String,
    request_id: RequestId,
    redirect_uri: String,
}

impl PasswordResetCompleteRequest {
    /// Constructs a password-reset completion request.
    #[must_use]
    pub fn new(
        token: impl Into<String>,
        new_password: impl Into<String>,
        request_id: RequestId,
        redirect_uri: impl Into<String>,
    ) -> Self {
        Self {
            token: token.into(),
            new_password: new_password.into(),
            request_id,
            redirect_uri: redirect_uri.into(),
        }
    }
}

impl fmt::Debug for PasswordResetCompleteRequest {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordResetCompleteRequest")
            .field("token", &"[REDACTED]")
            .field("new_password", &"[REDACTED]")
            .field("request_id", &self.request_id)
            .field("redirect_uri", &self.redirect_uri)
            .finish()
    }
}

impl Drop for PasswordResetCompleteRequest {
    fn drop(&mut self) {
        self.token.zeroize();
        self.new_password.zeroize();
    }
}

/// Successful browser password-login result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordLoginReceipt {
    /// Newly issued opaque session identifier.
    pub session_id: SessionId,
    /// Authenticated global user identifier.
    pub user_id: UserId,
    /// Session expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Validated local redirect path.
    pub redirect_uri: String,
}

/// Successful email-verification session result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EmailVerificationReceipt {
    /// Newly issued session identifier.
    pub session_id: SessionId,
    /// Verified global user identifier.
    pub user_id: UserId,
    /// Session expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Validated local redirect path.
    pub redirect_uri: String,
}

/// Generic password-reset start result.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct PasswordResetStartReceipt {
    /// Always true for a structurally valid public request.
    pub accepted: bool,
    /// Public reset-token lifetime.
    pub expires_in_seconds: u64,
}

/// Successful password reset and session rotation result.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasswordResetReceipt {
    /// Newly issued session identifier.
    pub session_id: SessionId,
    /// Reset account identifier.
    pub user_id: UserId,
    /// Session expiry in Unix milliseconds.
    pub expires_at_ms: u64,
    /// Validated local redirect path.
    pub redirect_uri: String,
}

struct PasswordLoginRecord {
    user_id: UserId,
    status: String,
    password_hash: String,
}

impl fmt::Debug for PasswordLoginRecord {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasswordLoginRecord")
            .field("user_id", &self.user_id)
            .field("status", &self.status)
            .field("password_hash", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PasswordLoginRecord {
    fn drop(&mut self) {
        self.password_hash.zeroize();
    }
}

/// Product-level password registration service.
pub struct PasswordRegistrationService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
    argon2: Argon2Policy,
    outbox_key: OutboxSealingKey,
}

impl<T, C, R> PasswordRegistrationService<T, C, R> {
    /// Assembles the service from its concrete dependencies.
    #[must_use]
    pub const fn new(
        store: PostgresAuthStore<T>,
        clock: C,
        randomness: R,
        argon2: Argon2Policy,
        outbox_key: OutboxSealingKey,
    ) -> Self {
        Self {
            store,
            clock,
            randomness,
            argon2,
            outbox_key,
        }
    }

    /// Returns the underlying relational store.
    #[must_use]
    pub const fn store(&self) -> &PostgresAuthStore<T> {
        &self.store
    }
}

impl<T, C, R> PasswordRegistrationService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Registers an account and durably queues verification mail in one
    /// PostgreSQL statement. No raw token is returned to the caller.
    ///
    /// # Errors
    ///
    /// Returns a validation, randomness, crypto, or relational-store failure.
    pub async fn register(
        &self,
        request: PasswordRegistrationRequest,
    ) -> Result<RegistrationReceipt, PasswordRegistrationError<T::Error>> {
        validate_request(&request)?;
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let normalized_email = request.email.trim().to_ascii_lowercase();

        let mut password_salt = [0_u8; PASSWORD_SALT_BYTES];
        let mut verification_token = [0_u8; VERIFICATION_TOKEN_BYTES];
        let mut outbox_nonce = [0_u8; OUTBOX_NONCE_BYTES];
        fill(&self.randomness, &mut password_salt)?;
        fill(&self.randomness, &mut verification_token)?;
        fill(&self.randomness, &mut outbox_nonce)?;

        let password_hash = hash_password(&request.password, password_salt, self.argon2)
            .map_err(|_| PasswordRegistrationError::Crypto)?;
        let verification_token_text = URL_SAFE_NO_PAD.encode(verification_token);
        let verification_token_hash = Sha256::digest(verification_token_text.as_bytes()).into();
        let mail_payload = serde_json::to_vec(&json!({
            "version": 1,
            "kind": "email_verification",
            "recipient": normalized_email,
            "token": verification_token_text,
            "redirect_uri": request.redirect_uri,
        }))
        .map_err(|_| PasswordRegistrationError::Crypto)?;
        let outbox_payload = self
            .outbox_key
            .seal(outbox_nonce, &mail_payload)
            .map_err(|_| PasswordRegistrationError::Crypto)?;

        let user_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordRegistrationError::RandomnessUnavailable)?;
        let outbox_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordRegistrationError::RandomnessUnavailable)?;
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordRegistrationError::RandomnessUnavailable)?;
        let request_hash =
            registration_request_hash(&normalized_email, &request.password, &request.redirect_uri);
        let context = CommandContext::new(
            request.idempotency_key.clone(),
            request.actor_key.clone(),
            request_hash,
            request.request_id.clone(),
            now_ms,
            now_ms.saturating_add(IDEMPOTENCY_TTL_MS),
        )
        .map_err(|_| PasswordRegistrationError::InvalidRequest)?;
        let command = RegisterPasswordCommand {
            context,
            user_id,
            normalized_email: normalized_email.clone(),
            primary_email: request.email.trim().to_owned(),
            password_hash,
            verification_token_hash,
            redirect_uri: request.redirect_uri.clone(),
            verification_expires_at_ms: now_ms.saturating_add(EMAIL_VERIFICATION_TTL_MS),
            outbox_id,
            outbox_deduplication_key: format!("email-verification:{user_id}:v1"),
            outbox_payload,
            audit_id,
            audit_metadata: json!({"channel":"password"}),
        };
        self.store
            .register_password(command)
            .await
            .map_err(PasswordRegistrationError::Store)
    }

    /// Rotates the verification token and queues another message when the
    /// account is still pending. Missing, active, and rate-limited accounts
    /// produce the same successful result and no mail.
    ///
    /// # Errors
    ///
    /// Returns validation, randomness, crypto, or PostgreSQL failures.
    pub async fn resend_verification(
        &self,
        request: EmailVerificationResendRequest,
    ) -> Result<(), PasswordRegistrationError<T::Error>> {
        validate_resend_request(&request)?;
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let normalized_email = request.email.trim().to_ascii_lowercase();
        let mut token = [0_u8; VERIFICATION_TOKEN_BYTES];
        let mut nonce = [0_u8; OUTBOX_NONCE_BYTES];
        fill(&self.randomness, &mut token)?;
        fill(&self.randomness, &mut nonce)?;
        let token_text = URL_SAFE_NO_PAD.encode(token);
        let token_hash: [u8; 32] = Sha256::digest(token_text.as_bytes()).into();
        let mail_payload = serde_json::to_vec(&json!({
            "version": 1,
            "kind": "email_verification",
            "recipient": normalized_email,
            "token": token_text,
            "redirect_uri": request.redirect_uri,
        }))
        .map_err(|_| PasswordRegistrationError::Crypto)?;
        let outbox_payload = self
            .outbox_key
            .seal(nonce, &mail_payload)
            .map_err(|_| PasswordRegistrationError::Crypto)?;
        let outbox_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordRegistrationError::RandomnessUnavailable)?;
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordRegistrationError::RandomnessUnavailable)?;
        let email_hash = URL_SAFE_NO_PAD.encode(Sha256::digest(normalized_email.as_bytes()));
        self.store
            .transport()
            .query(
                RESEND_EMAIL_VERIFICATION_SQL,
                vec![
                    PgValue::Text(normalized_email),
                    PgValue::Bytes(token_hash.to_vec()),
                    PgValue::Text(request.redirect_uri),
                    PgValue::I64(u64_to_i64(now_ms.saturating_add(EMAIL_VERIFICATION_TTL_MS))),
                    PgValue::Text(outbox_id.to_string()),
                    PgValue::Text(format!("email-verification-resend:{outbox_id}")),
                    PgValue::Text(outbox_payload.key_version),
                    PgValue::Bytes(outbox_payload.ciphertext),
                    PgValue::Text(audit_id.to_string()),
                    PgValue::Text(request.request_id.as_str().to_owned()),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::Text(format!("verification-resend:{email_hash}")),
                ],
            )
            .await
            .map_err(|error| {
                PasswordRegistrationError::Store(PostgresStoreError::Transport(error))
            })?;
        Ok(())
    }
}

/// Password authentication service using one read and one atomic write.
pub struct PasswordLoginService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
    argon2: Argon2Policy,
    session_ttl_ms: u64,
}

impl<T, C, R> PasswordLoginService<T, C, R> {
    /// Assembles a password-login service with a one-hour session lifetime.
    #[must_use]
    pub const fn new(
        store: PostgresAuthStore<T>,
        clock: C,
        randomness: R,
        argon2: Argon2Policy,
    ) -> Self {
        Self {
            store,
            clock,
            randomness,
            argon2,
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
        }
    }

    /// Overrides the session lifetime after bounded validation.
    ///
    /// # Errors
    ///
    /// Rejects values outside five minutes through 24 hours.
    pub fn with_session_ttl_seconds(
        mut self,
        seconds: u64,
    ) -> Result<Self, PasswordLoginError<T::Error>>
    where
        T: PostgresTransport,
    {
        if !(5 * 60..=24 * 60 * 60).contains(&seconds) {
            return Err(PasswordLoginError::InvalidConfiguration);
        }
        self.session_ttl_ms = seconds.saturating_mul(1_000);
        Ok(self)
    }

    /// Returns the relational store used by this service.
    #[must_use]
    pub const fn store(&self) -> &PostgresAuthStore<T> {
        &self.store
    }
}

impl<T, C, R> PasswordLoginService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Verifies Argon2id credentials and issues a session atomically.
    ///
    /// Missing, pending, disabled, stale, and wrong-password accounts all
    /// consume an Argon2id verification and return the same failure.
    ///
    /// # Errors
    ///
    /// Returns a bounded request, credential, randomness, crypto, row, or
    /// transport failure.
    pub async fn login(
        &self,
        request: PasswordLoginRequest,
    ) -> Result<PasswordLoginReceipt, PasswordLoginError<T::Error>> {
        validate_login_request(&request)?;
        let normalized_email = request.email.trim().to_ascii_lowercase();
        let record = self.load_record(&normalized_email).await?;
        let candidate_hash = record
            .as_ref()
            .map_or(DUMMY_PASSWORD_HASH, |record| record.password_hash.as_str());
        let verified = verify_password(&request.password, candidate_hash, self.argon2)
            .map_err(|_| PasswordLoginError::Crypto)?;
        let Some(record) = record else {
            return Err(PasswordLoginError::InvalidCredentials);
        };
        if !verified || record.status != "active" {
            return Err(PasswordLoginError::InvalidCredentials);
        }

        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let session_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordLoginError::RandomnessUnavailable)?;
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordLoginError::RandomnessUnavailable)?;
        let expires_at_ms = now_ms.saturating_add(self.session_ttl_ms);
        let rows = self
            .store
            .transport()
            .query(
                ISSUE_PASSWORD_SESSION_SQL,
                vec![
                    PgValue::Text(record.user_id.as_str().to_owned()),
                    PgValue::Text(normalized_email),
                    PgValue::Text(record.password_hash.clone()),
                    PgValue::Text(session_id.to_string()),
                    PgValue::I64(u64_to_i64(expires_at_ms)),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::Text(audit_id.to_string()),
                    PgValue::Text(request.request_id.as_str().to_owned()),
                ],
            )
            .await
            .map_err(PasswordLoginError::Transport)?;
        let row = rows.first().ok_or(PasswordLoginError::InvalidCredentials)?;
        if row.required_text("outcome")? != "created" {
            return Err(PasswordLoginError::InvalidCredentials);
        }
        Ok(PasswordLoginReceipt {
            session_id: SessionId::new(row.required_text("session_id")?)?,
            user_id: UserId::new(row.required_text("user_id")?)?,
            expires_at_ms: i64_to_u64(row.required_i64("expires_at_ms")?)?,
            redirect_uri: request.redirect_uri.clone(),
        })
    }

    /// Changes a password after current-password and AAL2 session validation,
    /// rotates the account security revision, and revokes every other session.
    ///
    /// # Errors
    ///
    /// Returns invalid request/credentials, randomness, cryptography, malformed
    /// row, or PostgreSQL failures.
    pub async fn change_password(
        &self,
        request: PasswordChangeRequest,
    ) -> Result<(), PasswordLoginError<T::Error>> {
        if request.current_password.is_empty()
            || !(15..=128).contains(&request.new_password.chars().count())
            || request.current_password == request.new_password
        {
            return Err(PasswordLoginError::InvalidRequest);
        }
        let record = self.load_record_by_user(&request.user_id).await?;
        let candidate_hash = record
            .as_ref()
            .map_or(DUMMY_PASSWORD_HASH, |record| record.password_hash.as_str());
        let verified = verify_password(&request.current_password, candidate_hash, self.argon2)
            .map_err(|_| PasswordLoginError::Crypto)?;
        let Some(record) = record else {
            return Err(PasswordLoginError::InvalidCredentials);
        };
        if !verified || record.status != "active" {
            return Err(PasswordLoginError::InvalidCredentials);
        }
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let mut salt = [0_u8; PASSWORD_SALT_BYTES];
        self.randomness
            .fill_bytes(&mut salt)
            .map_err(|_| PasswordLoginError::RandomnessUnavailable)?;
        let new_hash = hash_password(&request.new_password, salt, self.argon2)
            .map_err(|_| PasswordLoginError::Crypto)?;
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordLoginError::RandomnessUnavailable)?;
        let rows = self
            .store
            .transport()
            .query(
                CHANGE_PASSWORD_SQL,
                vec![
                    PgValue::Text(request.user_id.as_str().to_owned()),
                    PgValue::Text(request.session_id.as_str().to_owned()),
                    PgValue::Text(record.password_hash.clone()),
                    PgValue::Text(new_hash),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::Text(audit_id.to_string()),
                    PgValue::Text(request.request_id.as_str().to_owned()),
                ],
            )
            .await
            .map_err(PasswordLoginError::Transport)?;
        if rows
            .first()
            .is_some_and(|row| row.required_text("outcome").ok() == Some("changed"))
        {
            Ok(())
        } else {
            Err(PasswordLoginError::InvalidCredentials)
        }
    }

    async fn load_record(
        &self,
        normalized_email: &str,
    ) -> Result<Option<PasswordLoginRecord>, PasswordLoginError<T::Error>> {
        let rows = self
            .store
            .transport()
            .query(
                LOAD_PASSWORD_LOGIN_SQL,
                vec![PgValue::Text(normalized_email.to_owned())],
            )
            .await
            .map_err(PasswordLoginError::Transport)?;
        rows.first()
            .map(|row| {
                Ok(PasswordLoginRecord {
                    user_id: UserId::new(row.required_text("user_id")?)?,
                    status: row.required_text("status")?.to_owned(),
                    password_hash: row.required_text("password_hash")?.to_owned(),
                })
            })
            .transpose()
    }

    async fn load_record_by_user(
        &self,
        user_id: &UserId,
    ) -> Result<Option<PasswordLoginRecord>, PasswordLoginError<T::Error>> {
        let rows = self
            .store
            .transport()
            .query(
                LOAD_PASSWORD_BY_USER_SQL,
                vec![PgValue::Text(user_id.as_str().to_owned())],
            )
            .await
            .map_err(PasswordLoginError::Transport)?;
        rows.first()
            .map(|row| {
                Ok(PasswordLoginRecord {
                    user_id: UserId::new(row.required_text("user_id")?)?,
                    status: row.required_text("status")?.to_owned(),
                    password_hash: row.required_text("password_hash")?.to_owned(),
                })
            })
            .transpose()
    }
}

/// One-time email verification and browser-session service.
pub struct EmailVerificationService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
    session_ttl_ms: u64,
    bootstrap_system_administrator_emails: Vec<String>,
}

impl<T, C, R> EmailVerificationService<T, C, R> {
    /// Assembles the service with a one-hour session lifetime.
    #[must_use]
    pub const fn new(store: PostgresAuthStore<T>, clock: C, randomness: R) -> Self {
        Self {
            store,
            clock,
            randomness,
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
            bootstrap_system_administrator_emails: Vec::new(),
        }
    }

    /// Configures the bounded set of users promoted to system administrator
    /// when they complete email verification.
    ///
    /// Promotion is committed atomically with activation and session creation.
    /// This is intended only for initial deployment bootstrap; subsequent
    /// administrator grants should use the audited management workflow.
    ///
    /// # Errors
    ///
    /// Rejects more than 100 entries or malformed email addresses.
    pub fn with_bootstrap_system_administrator_emails<I, S>(
        mut self,
        emails: I,
    ) -> Result<Self, EmailVerificationError<T::Error>>
    where
        T: PostgresTransport,
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let mut normalized = Vec::new();
        for email in emails {
            let email = email.as_ref().trim().to_ascii_lowercase();
            if !valid_bootstrap_email(&email) {
                return Err(EmailVerificationError::InvalidConfiguration);
            }
            if !normalized.contains(&email) {
                if normalized.len() == 100 {
                    return Err(EmailVerificationError::InvalidConfiguration);
                }
                normalized.push(email);
            }
        }
        self.bootstrap_system_administrator_emails = normalized;
        Ok(self)
    }

    /// Overrides the session lifetime after bounded validation.
    ///
    /// # Errors
    ///
    /// Rejects values outside five minutes through 24 hours.
    pub fn with_session_ttl_seconds(
        mut self,
        seconds: u64,
    ) -> Result<Self, EmailVerificationError<T::Error>>
    where
        T: PostgresTransport,
    {
        if !(5 * 60..=24 * 60 * 60).contains(&seconds) {
            return Err(EmailVerificationError::InvalidConfiguration);
        }
        self.session_ttl_ms = seconds.saturating_mul(1_000);
        Ok(self)
    }

    /// Returns the relational store used by this service.
    #[must_use]
    pub const fn store(&self) -> &PostgresAuthStore<T> {
        &self.store
    }
}

impl<T, C, R> EmailVerificationService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Consumes a verification token and issues a session in one statement.
    /// Every subsequent use of the opaque token is rejected.
    ///
    /// # Errors
    ///
    /// Returns request, token, randomness, row, context, or transport failure.
    pub async fn verify(
        &self,
        request: EmailVerificationRequest,
    ) -> Result<EmailVerificationReceipt, EmailVerificationError<T::Error>> {
        validate_verification_request(&request)?;
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let expires_at_ms = now_ms.saturating_add(self.session_ttl_ms);
        let session_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| EmailVerificationError::RandomnessUnavailable)?;
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| EmailVerificationError::RandomnessUnavailable)?;
        let token_hash = Sha256::digest(request.token.trim().as_bytes()).to_vec();
        let rows = self
            .store
            .transport()
            .query(
                VERIFY_EMAIL_SQL,
                vec![
                    PgValue::Bytes(token_hash),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::Text(session_id.to_string()),
                    PgValue::I64(u64_to_i64(expires_at_ms)),
                    PgValue::Text(audit_id.to_string()),
                    PgValue::Text(request.request_id.as_str().to_owned()),
                    PgValue::Json(json!(self.bootstrap_system_administrator_emails)),
                ],
            )
            .await
            .map_err(EmailVerificationError::Transport)?;
        let row = rows.first().ok_or(EmailVerificationError::InvalidToken)?;
        if row.required_text("outcome")? != "created" {
            return Err(EmailVerificationError::InvalidToken);
        }
        Ok(EmailVerificationReceipt {
            session_id: SessionId::new(row.required_text("session_id")?)?,
            user_id: UserId::new(row.required_text("user_id")?)?,
            expires_at_ms: i64_to_u64(row.required_i64("expires_at_ms")?)?,
            redirect_uri: request.redirect_uri.clone(),
        })
    }
}

fn valid_bootstrap_email(email: &str) -> bool {
    if email.is_empty() || email.len() > 320 || email.chars().any(char::is_whitespace) {
        return false;
    }
    let Some((local, domain)) = email.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && !domain.is_empty()
        && domain.contains('.')
        && !domain.starts_with('.')
        && !domain.ends_with('.')
        && !domain.contains("..")
        && !domain.contains('@')
}

/// Password reset start/completion and session-rotation service.
pub struct PasswordResetService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
    argon2: Argon2Policy,
    outbox_key: OutboxSealingKey,
    session_ttl_ms: u64,
}

impl<T, C, R> PasswordResetService<T, C, R> {
    /// Assembles the service with a one-hour post-reset session lifetime.
    #[must_use]
    pub const fn new(
        store: PostgresAuthStore<T>,
        clock: C,
        randomness: R,
        argon2: Argon2Policy,
        outbox_key: OutboxSealingKey,
    ) -> Self {
        Self {
            store,
            clock,
            randomness,
            argon2,
            outbox_key,
            session_ttl_ms: DEFAULT_SESSION_TTL_MS,
        }
    }

    /// Overrides the post-reset session lifetime after bounded validation.
    ///
    /// # Errors
    ///
    /// Rejects values outside five minutes through 24 hours.
    pub fn with_session_ttl_seconds(
        mut self,
        seconds: u64,
    ) -> Result<Self, PasswordResetError<T::Error>>
    where
        T: PostgresTransport,
    {
        if !(5 * 60..=24 * 60 * 60).contains(&seconds) {
            return Err(PasswordResetError::InvalidConfiguration);
        }
        self.session_ttl_ms = seconds.saturating_mul(1_000);
        Ok(self)
    }

    /// Returns the relational store used by this service.
    #[must_use]
    pub const fn store(&self) -> &PostgresAuthStore<T> {
        &self.store
    }
}

impl<T, C, R> PasswordResetService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Queues reset mail when an eligible account exists while returning the
    /// same accepted result for unknown or unavailable accounts.
    ///
    /// # Errors
    ///
    /// Returns validation, randomness, crypto, or PostgreSQL failures.
    pub async fn start(
        &self,
        request: PasswordResetStartRequest,
    ) -> Result<PasswordResetStartReceipt, PasswordResetError<T::Error>> {
        validate_reset_start(&request)?;
        let normalized_email = request.email.trim().to_ascii_lowercase();
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let mut raw_token = [0_u8; VERIFICATION_TOKEN_BYTES];
        let mut outbox_nonce = [0_u8; OUTBOX_NONCE_BYTES];
        self.randomness
            .fill_bytes(&mut raw_token)
            .map_err(|_| PasswordResetError::RandomnessUnavailable)?;
        self.randomness
            .fill_bytes(&mut outbox_nonce)
            .map_err(|_| PasswordResetError::RandomnessUnavailable)?;
        let token = URL_SAFE_NO_PAD.encode(raw_token);
        let token_hash = Sha256::digest(token.as_bytes()).to_vec();
        let outbox_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordResetError::RandomnessUnavailable)?;
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordResetError::RandomnessUnavailable)?;
        let payload = serde_json::to_vec(&json!({
            "version": 1,
            "kind": "password_reset",
            "recipient": normalized_email,
            "token": token,
            "redirect_uri": request.redirect_uri,
        }))
        .map_err(|_| PasswordResetError::Crypto)?;
        let sealed = self
            .outbox_key
            .seal(outbox_nonce, &payload)
            .map_err(|_| PasswordResetError::Crypto)?;
        self.store
            .transport()
            .query(
                START_PASSWORD_RESET_SQL,
                vec![
                    PgValue::Text(normalized_email),
                    PgValue::Bytes(token_hash),
                    PgValue::Text(request.redirect_uri),
                    PgValue::I64(u64_to_i64(now_ms.saturating_add(PASSWORD_RESET_TTL_MS))),
                    PgValue::Text(outbox_id.to_string()),
                    PgValue::Text(format!("password-reset:{outbox_id}")),
                    PgValue::Text(sealed.key_version),
                    PgValue::Bytes(sealed.ciphertext),
                    PgValue::Text(audit_id.to_string()),
                    PgValue::Text(request.request_id.as_str().to_owned()),
                    PgValue::I64(u64_to_i64(now_ms)),
                ],
            )
            .await
            .map_err(PasswordResetError::Transport)?;
        Ok(PasswordResetStartReceipt {
            accepted: true,
            expires_in_seconds: PASSWORD_RESET_TTL_MS / 1_000,
        })
    }

    /// Consumes a reset token, changes the password, increments the account
    /// security revision, revokes every prior session/refresh token, and issues
    /// one new session in a single statement.
    ///
    /// # Errors
    ///
    /// Returns request, token, randomness, crypto, row, context, or PostgreSQL
    /// failures.
    pub async fn complete(
        &self,
        request: PasswordResetCompleteRequest,
    ) -> Result<PasswordResetReceipt, PasswordResetError<T::Error>> {
        validate_reset_complete(&request)?;
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let mut salt = [0_u8; PASSWORD_SALT_BYTES];
        self.randomness
            .fill_bytes(&mut salt)
            .map_err(|_| PasswordResetError::RandomnessUnavailable)?;
        let password_hash = hash_password(&request.new_password, salt, self.argon2)
            .map_err(|_| PasswordResetError::Crypto)?;
        let session_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordResetError::RandomnessUnavailable)?;
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| PasswordResetError::RandomnessUnavailable)?;
        let rows = self
            .store
            .transport()
            .query(
                COMPLETE_PASSWORD_RESET_SQL,
                vec![
                    PgValue::Bytes(Sha256::digest(request.token.trim().as_bytes()).to_vec()),
                    PgValue::I64(u64_to_i64(now_ms)),
                    PgValue::Text(password_hash),
                    PgValue::Text(session_id.to_string()),
                    PgValue::I64(u64_to_i64(now_ms.saturating_add(self.session_ttl_ms))),
                    PgValue::Text(audit_id.to_string()),
                    PgValue::Text(request.request_id.as_str().to_owned()),
                ],
            )
            .await
            .map_err(PasswordResetError::Transport)?;
        let row = rows.first().ok_or(PasswordResetError::InvalidToken)?;
        if row.required_text("outcome")? != "created" {
            return Err(PasswordResetError::InvalidToken);
        }
        Ok(PasswordResetReceipt {
            session_id: SessionId::new(row.required_text("session_id")?)?,
            user_id: UserId::new(row.required_text("user_id")?)?,
            expires_at_ms: i64_to_u64(row.required_i64("expires_at_ms")?)?,
            redirect_uri: request.redirect_uri.clone(),
        })
    }
}

fn validate_request<E>(
    request: &PasswordRegistrationRequest,
) -> Result<(), PasswordRegistrationError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let email = request.email.trim();
    let valid_email = email.len() <= 320
        && !email.chars().any(char::is_control)
        && email.split_once('@').is_some_and(|(local, domain)| {
            !local.is_empty() && !domain.is_empty() && domain.contains('.')
        });
    if !valid_email
        || !(15..=128).contains(&request.password.chars().count())
        || request.redirect_uri.is_empty()
        || !request.redirect_uri.starts_with('/')
        || request.redirect_uri.starts_with("//")
        || request.redirect_uri.chars().any(char::is_control)
    {
        return Err(PasswordRegistrationError::InvalidRequest);
    }
    Ok(())
}

fn validate_login_request<E>(request: &PasswordLoginRequest) -> Result<(), PasswordLoginError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let email = request.email.trim();
    if email.len() > 320
        || email.split_once('@').is_none()
        || request.password.is_empty()
        || request.password.chars().count() > 128
        || request.redirect_uri.is_empty()
        || !request.redirect_uri.starts_with('/')
        || request.redirect_uri.starts_with("//")
        || request.redirect_uri.chars().any(char::is_control)
    {
        return Err(PasswordLoginError::InvalidRequest);
    }
    Ok(())
}

fn validate_resend_request<E>(
    request: &EmailVerificationResendRequest,
) -> Result<(), PasswordRegistrationError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let email = request.email.trim();
    if email.len() > 320
        || email.split_once('@').is_none_or(|(local, domain)| {
            local.is_empty() || domain.is_empty() || !domain.contains('.')
        })
        || request.redirect_uri.is_empty()
        || !request.redirect_uri.starts_with('/')
        || request.redirect_uri.starts_with("//")
        || request.redirect_uri.chars().any(char::is_control)
    {
        return Err(PasswordRegistrationError::InvalidRequest);
    }
    Ok(())
}

fn validate_verification_request<E>(
    request: &EmailVerificationRequest,
) -> Result<(), EmailVerificationError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    if request.token.trim().len() < 32
        || request.token.len() > 512
        || request.token.chars().any(char::is_control)
        || request.redirect_uri.is_empty()
        || !request.redirect_uri.starts_with('/')
        || request.redirect_uri.starts_with("//")
        || request.redirect_uri.chars().any(char::is_control)
    {
        return Err(EmailVerificationError::InvalidRequest);
    }
    Ok(())
}

fn validate_reset_start<E>(request: &PasswordResetStartRequest) -> Result<(), PasswordResetError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let email = request.email.trim();
    if email.len() > 320
        || email.split_once('@').is_none_or(|(local, domain)| {
            local.is_empty() || domain.is_empty() || !domain.contains('.')
        })
        || request.redirect_uri.is_empty()
        || !request.redirect_uri.starts_with('/')
        || request.redirect_uri.starts_with("//")
        || request.redirect_uri.chars().any(char::is_control)
    {
        return Err(PasswordResetError::InvalidRequest);
    }
    Ok(())
}

fn validate_reset_complete<E>(
    request: &PasswordResetCompleteRequest,
) -> Result<(), PasswordResetError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    if request.token.trim().len() < 32
        || request.token.len() > 512
        || request.token.chars().any(char::is_control)
        || !(15..=128).contains(&request.new_password.chars().count())
        || request.redirect_uri.is_empty()
        || !request.redirect_uri.starts_with('/')
        || request.redirect_uri.starts_with("//")
        || request.redirect_uri.chars().any(char::is_control)
    {
        return Err(PasswordResetError::InvalidRequest);
    }
    Ok(())
}

fn hash_password(
    password: &str,
    salt: [u8; PASSWORD_SALT_BYTES],
    policy: Argon2Policy,
) -> Result<String, PasswordCryptoError> {
    let mut output = [0_u8; PASSWORD_HASH_BYTES];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, policy.params()?)
        .hash_password_into(password.as_bytes(), &salt, &mut output)
        .map_err(|_| PasswordCryptoError)?;
    Ok(format!(
        "argon2id$m={},t={},p={}${}${}",
        policy.memory_kib,
        policy.iterations,
        policy.parallelism,
        URL_SAFE_NO_PAD.encode(salt),
        URL_SAFE_NO_PAD.encode(output),
    ))
}

fn verify_password(
    password: &str,
    stored_hash: &str,
    current_policy: Argon2Policy,
) -> Result<bool, PasswordCryptoError> {
    let parts = stored_hash.split('$').collect::<Vec<_>>();
    if parts.len() != 4 || parts[0] != "argon2id" {
        return Err(PasswordCryptoError);
    }
    let policy = parse_argon2_policy(parts[1])?;
    let salt = URL_SAFE_NO_PAD
        .decode(parts[2])
        .map_err(|_| PasswordCryptoError)?;
    let expected = URL_SAFE_NO_PAD
        .decode(parts[3])
        .map_err(|_| PasswordCryptoError)?;
    if expected.len() != PASSWORD_HASH_BYTES {
        return Err(PasswordCryptoError);
    }
    let mut candidate = [0_u8; PASSWORD_HASH_BYTES];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, policy.params()?)
        .hash_password_into(password.as_bytes(), &salt, &mut candidate)
        .map_err(|_| PasswordCryptoError)?;
    let different = candidate
        .iter()
        .zip(expected.iter())
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        });
    let _needs_rehash = policy.memory_kib < current_policy.memory_kib
        || policy.iterations < current_policy.iterations
        || policy.parallelism != current_policy.parallelism;
    Ok(different == 0)
}

fn parse_argon2_policy(value: &str) -> Result<Argon2Policy, PasswordCryptoError> {
    let mut memory_kib = None;
    let mut iterations = None;
    let mut parallelism = None;
    for part in value.split(',') {
        let (name, value) = part.split_once('=').ok_or(PasswordCryptoError)?;
        let value = value.parse::<u32>().map_err(|_| PasswordCryptoError)?;
        match name {
            "m" => memory_kib = Some(value),
            "t" => iterations = Some(value),
            "p" => parallelism = Some(value),
            _ => return Err(PasswordCryptoError),
        }
    }
    let policy = Argon2Policy {
        memory_kib: memory_kib.ok_or(PasswordCryptoError)?,
        iterations: iterations.ok_or(PasswordCryptoError)?,
        parallelism: parallelism.ok_or(PasswordCryptoError)?,
    };
    policy.params()?;
    Ok(policy)
}

fn registration_request_hash(email: &str, password: &str, redirect_uri: &str) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"wasi-auth:register-password:v1\0");
    update_bounded_hash(&mut digest, email.as_bytes());
    update_bounded_hash(&mut digest, password.as_bytes());
    update_bounded_hash(&mut digest, redirect_uri.as_bytes());
    digest.finalize().into()
}

fn update_bounded_hash(digest: &mut Sha256, value: &[u8]) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value);
}

fn u64_to_i64(value: u64) -> i64 {
    i64::try_from(value).unwrap_or(i64::MAX)
}

fn i64_to_u64(value: i64) -> Result<u64, RowDecodeError> {
    u64::try_from(value).map_err(|_| RowDecodeError::WrongType("timestamp"))
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

fn fill<R, E>(randomness: &R, destination: &mut [u8]) -> Result<(), PasswordRegistrationError<E>>
where
    R: RandomSource,
    E: StdError + Send + Sync + 'static,
{
    randomness
        .fill_bytes(destination)
        .map_err(|_| PasswordRegistrationError::RandomnessUnavailable)
}

#[derive(Clone, Copy, Debug, Error)]
#[error("password cryptographic operation failed")]
pub(crate) struct PasswordCryptoError;

/// Password-registration workflow failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PasswordRegistrationError<E: StdError + Send + Sync + 'static> {
    /// Public request fields violated bounds or redirect rules.
    #[error("password registration request is invalid")]
    InvalidRequest,
    /// KDF or encryption policy is invalid.
    #[error("password registration configuration is invalid")]
    InvalidConfiguration,
    /// Host cryptographic randomness was unavailable.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// Password hashing or outbox encryption failed.
    #[error("password registration cryptography failed")]
    Crypto,
    /// Relational command failed.
    #[error(transparent)]
    Store(#[from] PostgresStoreError<E>),
}

/// Password-login workflow failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PasswordLoginError<E: StdError + Send + Sync + 'static> {
    /// Public request fields violated bounds or redirect rules.
    #[error("password login request is invalid")]
    InvalidRequest,
    /// Session lifetime configuration is outside supported bounds.
    #[error("password login configuration is invalid")]
    InvalidConfiguration,
    /// Credentials or account state did not authenticate.
    #[error("email or password is invalid")]
    InvalidCredentials,
    /// Host cryptographic randomness was unavailable.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// Stored password material was malformed or verification failed.
    #[error("password verification failed")]
    Crypto,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL auth transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL returned malformed data.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// Stored identity violated bounded context rules.
    #[error("stored password identity is invalid")]
    Context,
}

impl<E> From<crate::context::ContextError> for PasswordLoginError<E>
where
    E: StdError + Send + Sync + 'static,
{
    fn from(_: crate::context::ContextError) -> Self {
        Self::Context
    }
}

/// Email-verification workflow failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum EmailVerificationError<E: StdError + Send + Sync + 'static> {
    /// Public request fields violated bounds or redirect rules.
    #[error("email verification request is invalid")]
    InvalidRequest,
    /// Session lifetime configuration is outside supported bounds.
    #[error("email verification configuration is invalid")]
    InvalidConfiguration,
    /// Opaque token is absent, expired, consumed without a replayable result,
    /// or belongs to an unavailable account.
    #[error("email verification token is invalid or expired")]
    InvalidToken,
    /// Host cryptographic randomness was unavailable.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL auth transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL returned malformed data.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// Stored identity violated bounded context rules.
    #[error("stored verification identity is invalid")]
    Context,
}

impl<E> From<crate::context::ContextError> for EmailVerificationError<E>
where
    E: StdError + Send + Sync + 'static,
{
    fn from(_: crate::context::ContextError) -> Self {
        Self::Context
    }
}

/// Password-reset workflow failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PasswordResetError<E: StdError + Send + Sync + 'static> {
    /// Public request fields violated bounds or redirect rules.
    #[error("password reset request is invalid")]
    InvalidRequest,
    /// Session lifetime or cryptographic configuration is invalid.
    #[error("password reset configuration is invalid")]
    InvalidConfiguration,
    /// Opaque token is absent, expired, or no longer replayable.
    #[error("password reset token is invalid or expired")]
    InvalidToken,
    /// Host cryptographic randomness was unavailable.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// Password hashing or outbox encryption failed.
    #[error("password reset cryptography failed")]
    Crypto,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL auth transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL returned malformed data.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// Stored identity violated bounded context rules.
    #[error("stored password reset identity is invalid")]
    Context,
}

impl<E> From<crate::context::ContextError> for PasswordResetError<E>
where
    E: StdError + Send + Sync + 'static,
{
    fn from(_: crate::context::ContextError) -> Self {
        Self::Context
    }
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeMap, convert::Infallible, sync::Mutex};

    use futures::executor::block_on;

    use super::*;
    use crate::postgres::{PgRow, PgValue};

    #[derive(Debug)]
    struct FixedClock;

    impl Clock for FixedClock {
        fn now_unix_seconds(&self) -> u64 {
            1_700_000_000
        }
    }

    #[derive(Debug)]
    struct FixedRandom(Mutex<u8>);

    impl FixedRandom {
        fn new() -> Self {
            Self(Mutex::new(1))
        }
    }

    impl RandomSource for FixedRandom {
        type Error = Infallible;

        fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), Self::Error> {
            let mut next = self.0.lock().expect("random lock");
            for byte in destination {
                *byte = *next;
                *next = next.wrapping_add(1);
            }
            Ok(())
        }
    }

    #[derive(Debug, Default)]
    struct RecordingTransport {
        calls: Mutex<usize>,
    }

    impl PostgresTransport for RecordingTransport {
        type Error = Infallible;

        async fn query(
            &self,
            _sql: &'static str,
            parameters: Vec<PgValue>,
        ) -> Result<Vec<PgRow>, Self::Error> {
            *self.calls.lock().expect("calls") += 1;
            let user_id = match &parameters[3] {
                PgValue::Text(value) => value.clone(),
                _ => panic!("user id is text"),
            };
            Ok(vec![PgRow::new(BTreeMap::from([
                ("outcome".to_owned(), PgValue::Text("created".to_owned())),
                ("user_id".to_owned(), PgValue::Text(user_id)),
            ]))])
        }
    }

    fn service() -> PasswordRegistrationService<RecordingTransport, FixedClock, FixedRandom> {
        PasswordRegistrationService::new(
            PostgresAuthStore::new(RecordingTransport::default()),
            FixedClock,
            FixedRandom::new(),
            Argon2Policy::default(),
            OutboxSealingKey::new("outbox-v1", [7; 32]).expect("valid key"),
        )
    }

    #[test]
    fn workflow_executes_one_atomic_command_and_redacts_request() {
        let service = service();
        let request = PasswordRegistrationRequest::new(
            "registration-1",
            "anonymous:fixture",
            RequestId::new("request-1").expect("request id"),
            "Person@Example.com",
            "correct horse battery staple",
            "/verify-email",
        );
        let debug = format!("{request:?}");

        let receipt = block_on(service.register(request)).expect("registration");

        assert!(!receipt.replayed);
        assert_eq!(*service.store().transport().calls.lock().expect("calls"), 1);
        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("correct horse"));
        assert!(!debug.contains("Person@Example.com"));
        let uuid = Uuid::parse_str(receipt.user_id.as_str()).expect("uuid");
        assert_eq!(uuid.get_version_num(), 7);
    }

    #[test]
    fn weak_password_is_rejected_before_storage() {
        let service = service();
        let request = PasswordRegistrationRequest::new(
            "registration-1",
            "anonymous:fixture",
            RequestId::new("request-1").expect("request id"),
            "person@example.com",
            "short",
            "/verify-email",
        );

        let result = block_on(service.register(request));

        assert!(matches!(
            result,
            Err(PasswordRegistrationError::InvalidRequest)
        ));
        assert_eq!(*service.store().transport().calls.lock().expect("calls"), 0);
    }

    #[derive(Debug)]
    struct LoginTransport {
        calls: Mutex<usize>,
        password_hash: String,
        user_id: Uuid,
    }

    impl PostgresTransport for LoginTransport {
        type Error = Infallible;

        async fn query(
            &self,
            sql: &'static str,
            parameters: Vec<PgValue>,
        ) -> Result<Vec<PgRow>, Self::Error> {
            let mut calls = self.calls.lock().expect("calls");
            *calls += 1;
            if sql == LOAD_PASSWORD_LOGIN_SQL {
                return Ok(vec![PgRow::new(BTreeMap::from([
                    (
                        "user_id".to_owned(),
                        PgValue::Text(self.user_id.to_string()),
                    ),
                    (
                        "primary_email".to_owned(),
                        PgValue::Text("person@example.com".to_owned()),
                    ),
                    ("status".to_owned(), PgValue::Text("active".to_owned())),
                    ("security_revision".to_owned(), PgValue::I64(1)),
                    (
                        "password_hash".to_owned(),
                        PgValue::Text(self.password_hash.clone()),
                    ),
                ]))]);
            }
            let session_id = match &parameters[3] {
                PgValue::Text(value) => value.clone(),
                _ => panic!("session id is text"),
            };
            Ok(vec![PgRow::new(BTreeMap::from([
                ("outcome".to_owned(), PgValue::Text("created".to_owned())),
                ("session_id".to_owned(), PgValue::Text(session_id)),
                (
                    "user_id".to_owned(),
                    PgValue::Text(self.user_id.to_string()),
                ),
                ("expires_at_ms".to_owned(), PgValue::I64(1_700_003_600_000)),
            ]))])
        }
    }

    fn login_service() -> PasswordLoginService<LoginTransport, FixedClock, FixedRandom> {
        let policy = Argon2Policy::default();
        PasswordLoginService::new(
            PostgresAuthStore::new(LoginTransport {
                calls: Mutex::new(0),
                password_hash: hash_password(
                    "correct horse battery staple",
                    [3; PASSWORD_SALT_BYTES],
                    policy,
                )
                .expect("password hash"),
                user_id: Uuid::now_v7(),
            }),
            FixedClock,
            FixedRandom::new(),
            policy,
        )
    }

    #[test]
    fn login_consumes_one_read_and_one_atomic_write() {
        let service = login_service();
        let request = PasswordLoginRequest::new(
            "person@example.com",
            "correct horse battery staple",
            RequestId::new("login-request-1").expect("request id"),
            "/organizations",
        );

        let receipt = block_on(service.login(request)).expect("login");

        assert_eq!(receipt.redirect_uri, "/organizations");
        assert_eq!(*service.store().transport().calls.lock().expect("calls"), 2);
    }

    #[test]
    fn wrong_password_never_executes_session_write() {
        let service = login_service();
        let request = PasswordLoginRequest::new(
            "person@example.com",
            "this is the wrong password",
            RequestId::new("login-request-2").expect("request id"),
            "/organizations",
        );

        let result = block_on(service.login(request));

        assert!(matches!(
            result,
            Err(PasswordLoginError::InvalidCredentials)
        ));
        assert_eq!(*service.store().transport().calls.lock().expect("calls"), 1);
    }
}
