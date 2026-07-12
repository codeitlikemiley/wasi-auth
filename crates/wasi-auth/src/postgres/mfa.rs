//! Encrypted TOTP enrollment, step-up, and one-time recovery codes.

use std::{error::Error as StdError, fmt};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use serde_json::Value;
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use super::{PgRow, PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};
use crate::{
    authentication::mfa::{
        RecoveryCode, TotpConfig, TotpSecret, hash_recovery_code, provisioning_uri, verify_totp,
    },
    authentication::{Clock, RandomSource},
    context::{RequestId, SessionId},
};

const MFA_STATUS_SQL: &str = include_str!("mfa_status.sql");
const START_TOTP_ENROLLMENT_SQL: &str = include_str!("start_totp_enrollment.sql");
const LOAD_TOTP_FACTOR_SQL: &str = include_str!("load_totp_factor.sql");
const CONFIRM_TOTP_ENROLLMENT_SQL: &str = include_str!("confirm_totp_enrollment.sql");
const VERIFY_TOTP_STEP_UP_SQL: &str = include_str!("verify_totp_step_up.sql");
const USE_RECOVERY_CODE_SQL: &str = include_str!("use_recovery_code.sql");
const MFA_AAD_PREFIX: &[u8] = b"wasi-auth:totp:v1:";
const NONCE_BYTES: usize = 12;
const UUID_RANDOM_BYTES: usize = 10;
const RECOVERY_CODE_COUNT: usize = 10;

/// Versioned TOTP encryption key and recovery-code pepper.
pub struct MfaKeyMaterial {
    version: String,
    encryption_key: [u8; 32],
    recovery_pepper: Vec<u8>,
}

impl MfaKeyMaterial {
    /// Constructs bounded MFA key material.
    ///
    /// # Errors
    ///
    /// Rejects invalid versions or recovery peppers shorter than 128 bits.
    pub fn new(
        version: impl Into<String>,
        encryption_key: [u8; 32],
        recovery_pepper: impl Into<Vec<u8>>,
    ) -> Result<Self, MfaConfigurationError> {
        let version = version.into();
        let recovery_pepper = recovery_pepper.into();
        if version.is_empty()
            || version.len() > 128
            || version.chars().any(char::is_control)
            || recovery_pepper.len() < 16
            || recovery_pepper.len() > 1_024
        {
            return Err(MfaConfigurationError::Invalid);
        }
        Ok(Self {
            version,
            encryption_key,
            recovery_pepper,
        })
    }

    fn encrypt(
        &self,
        user_id: &str,
        nonce: [u8; NONCE_BYTES],
        secret: &[u8],
    ) -> Result<Vec<u8>, ()> {
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key).map_err(|_| ())?;
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: secret,
                    aad: &factor_aad(user_id),
                },
            )
            .map_err(|_| ())?;
        let mut sealed = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn decrypt(&self, factor: &TotpFactor) -> Result<Vec<u8>, ()> {
        if factor.key_version != self.version || factor.ciphertext.len() <= NONCE_BYTES {
            return Err(());
        }
        let (nonce, ciphertext) = factor.ciphertext.split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| ())?;
        let cipher = Aes256Gcm::new_from_slice(&self.encryption_key).map_err(|_| ())?;
        cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &factor_aad(&factor.user_id),
                },
            )
            .map_err(|_| ())
    }
}

impl fmt::Debug for MfaKeyMaterial {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("MfaKeyMaterial")
            .field("version", &self.version)
            .field("encryption_key", &"[REDACTED]")
            .field("recovery_pepper", &"[REDACTED]")
            .finish()
    }
}

impl Drop for MfaKeyMaterial {
    fn drop(&mut self) {
        self.encryption_key.zeroize();
        self.recovery_pepper.zeroize();
    }
}

/// Current MFA state for one session user.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct MfaStatus {
    /// Whether a TOTP factor is enabled.
    pub totp_enrolled: bool,
    /// Unused recovery-code count.
    pub recovery_codes_remaining: u32,
    /// Current session assurance.
    pub assurance: String,
}

/// One-time TOTP enrollment response.
pub struct TotpEnrollment {
    /// Standards-compatible provisioning URI.
    pub provisioning_uri: String,
    /// Base32 secret for manual entry.
    pub secret_base32: String,
}

impl TotpEnrollment {
    /// Takes the provisioning URI and Base32 secret.
    pub fn into_parts(mut self) -> (String, String) {
        (
            std::mem::take(&mut self.provisioning_uri),
            std::mem::take(&mut self.secret_base32),
        )
    }
}

impl fmt::Debug for TotpEnrollment {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TotpEnrollment")
            .field("provisioning_uri", &"[REDACTED]")
            .field("secret_base32", &"[REDACTED]")
            .finish()
    }
}

impl Drop for TotpEnrollment {
    fn drop(&mut self) {
        self.provisioning_uri.zeroize();
        self.secret_base32.zeroize();
    }
}

/// Recovery codes displayed once after TOTP confirmation.
pub struct TotpConfirmation {
    /// Raw single-use recovery codes.
    pub recovery_codes: Vec<String>,
}

impl TotpConfirmation {
    /// Takes the one-time recovery codes.
    pub fn into_recovery_codes(mut self) -> Vec<String> {
        std::mem::take(&mut self.recovery_codes)
    }
}

impl fmt::Debug for TotpConfirmation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TotpConfirmation")
            .field("recovery_codes", &"[REDACTED]")
            .finish()
    }
}

impl Drop for TotpConfirmation {
    fn drop(&mut self) {
        self.recovery_codes.iter_mut().for_each(Zeroize::zeroize);
    }
}

struct TotpFactor {
    user_id: String,
    key_version: String,
    ciphertext: Vec<u8>,
    enabled: bool,
}

impl fmt::Debug for TotpFactor {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TotpFactor")
            .field("user_id", &self.user_id)
            .field("key_version", &self.key_version)
            .field("ciphertext", &"[REDACTED]")
            .field("enabled", &self.enabled)
            .finish()
    }
}

impl Drop for TotpFactor {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
    }
}

/// PostgreSQL MFA workflow service.
pub struct MfaService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
    keys: MfaKeyMaterial,
    config: TotpConfig,
    issuer: String,
}

impl<T, C, R> MfaService<T, C, R> {
    /// Assembles the service from validated dependencies.
    ///
    /// # Errors
    ///
    /// Rejects an empty or unbounded issuer.
    pub fn new(
        store: PostgresAuthStore<T>,
        clock: C,
        randomness: R,
        keys: MfaKeyMaterial,
        config: TotpConfig,
        issuer: impl Into<String>,
    ) -> Result<Self, MfaConfigurationError> {
        let issuer = issuer.into();
        if issuer.trim().is_empty() || issuer.len() > 128 || issuer.chars().any(char::is_control) {
            return Err(MfaConfigurationError::Invalid);
        }
        Ok(Self {
            store,
            clock,
            randomness,
            keys,
            config,
            issuer,
        })
    }
}

impl<T, C, R> MfaService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Loads MFA state from the authoritative session user.
    ///
    /// # Errors
    ///
    /// Returns invalid session, row, or transport failures.
    pub async fn status(
        &self,
        session_id: &SessionId,
    ) -> Result<MfaStatus, MfaServiceError<T::Error>> {
        let rows = self
            .query(
                MFA_STATUS_SQL,
                vec![text(session_id.as_str()), now_value(&self.clock)],
            )
            .await?;
        let row = rows.first().ok_or(MfaServiceError::InvalidSession)?;
        Ok(MfaStatus {
            totp_enrolled: row
                .bool("totp_enrolled")?
                .ok_or(MfaServiceError::InvalidRow)?,
            recovery_codes_remaining: u32::try_from(row.required_i64("recovery_codes_remaining")?)
                .map_err(|_| MfaServiceError::InvalidRow)?,
            assurance: row.required_text("assurance")?.to_owned(),
        })
    }

    /// Starts or replaces an unconfirmed TOTP enrollment.
    ///
    /// # Errors
    ///
    /// Returns conflict, session, crypto, randomness, row, or transport failures.
    pub async fn start(
        &self,
        session_id: &SessionId,
        request_id: &RequestId,
    ) -> Result<TotpEnrollment, MfaServiceError<T::Error>> {
        let now_seconds = self.clock.now_unix_seconds();
        let session = self
            .store
            .load_verified_session(session_id, request_id.clone(), now_seconds)
            .await
            .map_err(|_| MfaServiceError::InvalidSession)?;
        let secret = TotpSecret::generate(&self.randomness)
            .map_err(|_| MfaServiceError::RandomnessUnavailable)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        self.randomness
            .fill_bytes(&mut nonce)
            .map_err(|_| MfaServiceError::RandomnessUnavailable)?;
        let user_id = session.context().auth().principal().user_id().as_str();
        let ciphertext = self
            .keys
            .encrypt(user_id, nonce, secret.expose())
            .map_err(|_| MfaServiceError::Crypto)?;
        let now_ms = now_seconds.saturating_mul(1_000);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .query(
                START_TOTP_ENROLLMENT_SQL,
                vec![
                    text(session_id.as_str()),
                    text(&self.keys.version),
                    PgValue::Bytes(ciphertext),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        if rows
            .first()
            .and_then(|row| row.required_text("outcome").ok())
            != Some("started")
        {
            return Err(MfaServiceError::AlreadyEnrolled);
        }
        let uri = provisioning_uri(&self.issuer, session.primary_email(), &secret, self.config)
            .map_err(|_| MfaServiceError::Crypto)?;
        Ok(TotpEnrollment {
            provisioning_uri: uri,
            secret_base32: secret.provisioning_base32(),
        })
    }

    /// Confirms TOTP, rotates recovery codes, and elevates the session atomically.
    ///
    /// # Errors
    ///
    /// Returns invalid code/factor, crypto, randomness, row, or transport failures.
    pub async fn confirm(
        &self,
        session_id: &SessionId,
        code: &str,
        request_id: &RequestId,
    ) -> Result<TotpConfirmation, MfaServiceError<T::Error>> {
        let factor = self.load_factor(session_id).await?;
        if factor.enabled {
            return Err(MfaServiceError::AlreadyEnrolled);
        }
        self.verify_factor(&factor, code)?;
        let mut raw_codes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        let mut hashes = Vec::with_capacity(RECOVERY_CODE_COUNT);
        for _ in 0..RECOVERY_CODE_COUNT {
            let code = RecoveryCode::generate(&self.randomness)
                .map_err(|_| MfaServiceError::RandomnessUnavailable)?;
            let hash = hash_recovery_code(&self.keys.recovery_pepper, code.expose())
                .map_err(|_| MfaServiceError::Crypto)?;
            raw_codes.push(code.expose().to_owned());
            hashes.push(hex(hash.as_bytes()));
        }
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .query(
                CONFIRM_TOTP_ENROLLMENT_SQL,
                vec![
                    text(session_id.as_str()),
                    PgValue::Bytes(factor.ciphertext.clone()),
                    i64_value(now_ms),
                    PgValue::Json(Value::Array(
                        hashes.into_iter().map(Value::String).collect(),
                    )),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        if rows
            .first()
            .and_then(|row| row.required_text("outcome").ok())
            == Some("confirmed")
        {
            Ok(TotpConfirmation {
                recovery_codes: raw_codes,
            })
        } else {
            Err(MfaServiceError::InvalidFactor)
        }
    }

    /// Verifies TOTP and elevates the session to AAL2.
    ///
    /// # Errors
    ///
    /// Returns invalid code/factor, crypto, row, or transport failures.
    pub async fn verify_step_up(
        &self,
        session_id: &SessionId,
        code: &str,
        request_id: &RequestId,
    ) -> Result<(), MfaServiceError<T::Error>> {
        let factor = self.load_factor(session_id).await?;
        if !factor.enabled {
            return Err(MfaServiceError::InvalidFactor);
        }
        self.verify_factor(&factor, code)?;
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .query(
                VERIFY_TOTP_STEP_UP_SQL,
                vec![
                    text(session_id.as_str()),
                    PgValue::Bytes(factor.ciphertext.clone()),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        outcome(&rows, "elevated")
    }

    /// Consumes one recovery code and elevates the session to AAL2.
    ///
    /// # Errors
    ///
    /// Returns invalid/used code, session, row, or transport failures.
    pub async fn use_recovery_code(
        &self,
        session_id: &SessionId,
        code: &str,
        request_id: &RequestId,
    ) -> Result<(), MfaServiceError<T::Error>> {
        let hash = hash_recovery_code(&self.keys.recovery_pepper, code)
            .map_err(|_| MfaServiceError::InvalidCode)?;
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let audit_id = self.uuid(now_ms)?;
        let rows = self
            .query(
                USE_RECOVERY_CODE_SQL,
                vec![
                    text(session_id.as_str()),
                    PgValue::Bytes(hash.as_bytes().to_vec()),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        outcome(&rows, "elevated")
    }

    async fn load_factor(
        &self,
        session_id: &SessionId,
    ) -> Result<TotpFactor, MfaServiceError<T::Error>> {
        let rows = self
            .query(
                LOAD_TOTP_FACTOR_SQL,
                vec![text(session_id.as_str()), now_value(&self.clock)],
            )
            .await?;
        let row = rows.first().ok_or(MfaServiceError::InvalidFactor)?;
        Ok(TotpFactor {
            user_id: row.required_text("user_id")?.to_owned(),
            key_version: row.required_text("key_version")?.to_owned(),
            ciphertext: row.required_bytes("secret_ciphertext")?.to_vec(),
            enabled: row.i64("enabled_at_ms")?.is_some(),
        })
    }

    fn verify_factor(
        &self,
        factor: &TotpFactor,
        code: &str,
    ) -> Result<(), MfaServiceError<T::Error>> {
        let mut secret = self
            .keys
            .decrypt(factor)
            .map_err(|_| MfaServiceError::Crypto)?;
        let valid = verify_totp(&secret, code, self.clock.now_unix_seconds(), self.config)
            .map_err(|_| MfaServiceError::InvalidCode)?;
        secret.zeroize();
        if valid {
            Ok(())
        } else {
            Err(MfaServiceError::InvalidCode)
        }
    }

    async fn query(
        &self,
        sql: &'static str,
        values: Vec<PgValue>,
    ) -> Result<Vec<PgRow>, MfaServiceError<T::Error>> {
        self.store
            .transport()
            .query(sql, values)
            .await
            .map_err(MfaServiceError::Transport)
    }

    fn uuid(&self, now_ms: u64) -> Result<Uuid, MfaServiceError<T::Error>> {
        uuid_v7(now_ms, &self.randomness).map_err(|_| MfaServiceError::RandomnessUnavailable)
    }
}

fn outcome<E>(rows: &[PgRow], expected: &str) -> Result<(), MfaServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    if rows
        .first()
        .and_then(|row| row.required_text("outcome").ok())
        == Some(expected)
    {
        Ok(())
    } else {
        Err(MfaServiceError::InvalidCode)
    }
}

fn factor_aad(user_id: &str) -> Vec<u8> {
    let mut aad = Vec::with_capacity(MFA_AAD_PREFIX.len() + user_id.len());
    aad.extend_from_slice(MFA_AAD_PREFIX);
    aad.extend_from_slice(user_id.as_bytes());
    aad
}

fn hex(value: &[u8]) -> String {
    value.iter().map(|byte| format!("{byte:02x}")).collect()
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

fn text(value: impl ToString) -> PgValue {
    PgValue::Text(value.to_string())
}
fn i64_value(value: u64) -> PgValue {
    PgValue::I64(i64::try_from(value).unwrap_or(i64::MAX))
}
fn now_value<C: Clock>(clock: &C) -> PgValue {
    i64_value(clock.now_unix_seconds().saturating_mul(1_000))
}

/// Invalid MFA key or issuer configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum MfaConfigurationError {
    /// Configuration violated bounded policy.
    #[error("MFA configuration is invalid")]
    Invalid,
}

/// MFA persistence or verification failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MfaServiceError<E: StdError + Send + Sync + 'static> {
    /// Session is missing, expired, revoked, or stale.
    #[error("session is invalid")]
    InvalidSession,
    /// A TOTP factor is already enabled.
    #[error("TOTP is already enrolled")]
    AlreadyEnrolled,
    /// TOTP factor is absent, disabled, or changed concurrently.
    #[error("TOTP factor is invalid")]
    InvalidFactor,
    /// TOTP or recovery code is malformed, wrong, or already used.
    #[error("MFA code is invalid")]
    InvalidCode,
    /// Host randomness failed.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// MFA encryption or secret processing failed.
    #[error("MFA cryptography failed")]
    Crypto,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL MFA transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL row decoding failed.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned malformed MFA data.
    #[error("PostgreSQL returned malformed MFA data")]
    InvalidRow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_debug_redacts_secrets() {
        let key = MfaKeyMaterial::new("v1", [7; 32], [9; 32]).expect("valid key");
        let debug = format!("{key:?}");
        assert!(debug.contains("[REDACTED]"));
    }
}
