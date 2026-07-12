//! Encrypted, one-time state shared by OAuth and WebAuthn ceremonies.

use std::{error::Error as StdError, fmt};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::Zeroize;

use super::{PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};
use crate::authentication::{Clock, RandomSource};

const CREATE_AUTH_FLOW_SQL: &str = include_str!("create_auth_flow.sql");
const LOAD_AUTH_FLOW_SQL: &str = include_str!("load_auth_flow.sql");
const FLOW_AAD_PREFIX: &[u8] = b"wasi-auth:flow:v1:";
const NONCE_BYTES: usize = 12;
const VERIFIER_BYTES: usize = 32;
const UUID_RANDOM_BYTES: usize = 10;
const MAX_PAYLOAD_BYTES: usize = 64 * 1_024;

/// Versioned key used to seal short-lived OAuth and WebAuthn state.
pub struct FlowSealingKey {
    version: String,
    key: [u8; 32],
}

impl FlowSealingKey {
    /// Constructs a flow-state key.
    ///
    /// # Errors
    ///
    /// Rejects empty, unbounded, or control-character key versions.
    pub fn new(version: impl Into<String>, key: [u8; 32]) -> Result<Self, FlowConfigurationError> {
        let version = version.into();
        if version.is_empty() || version.len() > 128 || version.chars().any(char::is_control) {
            return Err(FlowConfigurationError::Invalid);
        }
        Ok(Self { version, key })
    }

    fn seal(
        &self,
        kind: FlowKind,
        flow_id: &Uuid,
        nonce: [u8; NONCE_BYTES],
        plaintext: &[u8],
    ) -> Result<Vec<u8>, ()> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| ())?;
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: &flow_aad(kind, flow_id),
                },
            )
            .map_err(|_| ())?;
        let mut sealed = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn open(
        &self,
        kind: FlowKind,
        flow_id: &Uuid,
        version: &str,
        sealed: &[u8],
    ) -> Result<Vec<u8>, ()> {
        if version != self.version || sealed.len() <= NONCE_BYTES {
            return Err(());
        }
        let (nonce, ciphertext) = sealed.split_at(NONCE_BYTES);
        let nonce: [u8; NONCE_BYTES] = nonce.try_into().map_err(|_| ())?;
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| ())?;
        cipher
            .decrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: ciphertext,
                    aad: &flow_aad(kind, flow_id),
                },
            )
            .map_err(|_| ())
    }
}

impl fmt::Debug for FlowSealingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("FlowSealingKey")
            .field("version", &self.version)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for FlowSealingKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FlowKind {
    OAuth,
    WebauthnRegistration,
    WebauthnAuthentication,
}

impl FlowKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::OAuth => "oauth",
            Self::WebauthnRegistration => "webauthn_registration",
            Self::WebauthnAuthentication => "webauthn_authentication",
        }
    }
}

pub(crate) struct PendingFlow {
    pub(crate) flow_id: Uuid,
    pub(crate) user_id: Option<String>,
    pub(crate) verifier_hash: Vec<u8>,
    pub(crate) payload: Vec<u8>,
}

impl fmt::Debug for PendingFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingFlow")
            .field("flow_id", &self.flow_id)
            .field("user_id", &self.user_id)
            .field("verifier_hash", &"[REDACTED]")
            .field("payload", &"[REDACTED]")
            .finish()
    }
}

impl Drop for PendingFlow {
    fn drop(&mut self) {
        self.payload.zeroize();
    }
}

pub(crate) struct EncryptedFlowStore<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
    key: FlowSealingKey,
}

impl<T, C, R> EncryptedFlowStore<T, C, R> {
    pub(crate) const fn new(
        store: PostgresAuthStore<T>,
        clock: C,
        randomness: R,
        key: FlowSealingKey,
    ) -> Self {
        Self {
            store,
            clock,
            randomness,
            key,
        }
    }

    pub(crate) const fn transport(&self) -> &T {
        self.store.transport()
    }

    pub(crate) const fn store(&self) -> &PostgresAuthStore<T> {
        &self.store
    }

    pub(crate) fn now_unix_seconds(&self) -> u64
    where
        C: Clock,
    {
        self.clock.now_unix_seconds()
    }

    pub(crate) fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), ()>
    where
        R: RandomSource,
    {
        self.randomness.fill_bytes(destination).map_err(|_| ())
    }

    pub(crate) fn uuid(&self, now_ms: u64) -> Result<Uuid, ()>
    where
        R: RandomSource,
    {
        uuid_v7(now_ms, &self.randomness)
    }
}

impl<T, C, R> EncryptedFlowStore<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    pub(crate) async fn create(
        &self,
        kind: FlowKind,
        user_id: Option<&str>,
        payload: &[u8],
        ttl_seconds: u64,
    ) -> Result<String, FlowStoreError<T::Error>> {
        if payload.is_empty()
            || payload.len() > MAX_PAYLOAD_BYTES
            || !(60..=15 * 60).contains(&ttl_seconds)
        {
            return Err(FlowStoreError::InvalidInput);
        }
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let flow_id =
            uuid_v7(now_ms, &self.randomness).map_err(|_| FlowStoreError::RandomnessUnavailable)?;
        let mut verifier = [0_u8; VERIFIER_BYTES];
        let mut nonce = [0_u8; NONCE_BYTES];
        self.randomness
            .fill_bytes(&mut verifier)
            .map_err(|_| FlowStoreError::RandomnessUnavailable)?;
        self.randomness
            .fill_bytes(&mut nonce)
            .map_err(|_| FlowStoreError::RandomnessUnavailable)?;
        let sealed = self
            .key
            .seal(kind, &flow_id, nonce, payload)
            .map_err(|_| FlowStoreError::Crypto)?;
        let verifier_text = URL_SAFE_NO_PAD.encode(verifier);
        let verifier_hash = Sha256::digest(verifier_text.as_bytes()).to_vec();
        verifier.zeroize();
        let rows = self
            .store
            .transport()
            .query(
                CREATE_AUTH_FLOW_SQL,
                vec![
                    text(flow_id),
                    text(kind.as_str()),
                    user_id.map_or(PgValue::Null, text),
                    PgValue::Bytes(verifier_hash),
                    text(&self.key.version),
                    PgValue::Bytes(sealed),
                    i64_value(now_ms.saturating_add(ttl_seconds.saturating_mul(1_000))),
                    i64_value(now_ms),
                ],
            )
            .await
            .map_err(FlowStoreError::Transport)?;
        if rows
            .first()
            .and_then(|row| row.required_text("outcome").ok())
            == Some("created")
        {
            Ok(verifier_text)
        } else {
            Err(FlowStoreError::InvalidRow)
        }
    }

    pub(crate) async fn load(
        &self,
        kind: FlowKind,
        verifier: &str,
    ) -> Result<PendingFlow, FlowStoreError<T::Error>> {
        if verifier.len() < 32 || verifier.len() > 512 || verifier.chars().any(char::is_control) {
            return Err(FlowStoreError::InvalidFlow);
        }
        let verifier_hash = Sha256::digest(verifier.as_bytes()).to_vec();
        let rows = self
            .store
            .transport()
            .query(
                LOAD_AUTH_FLOW_SQL,
                vec![
                    PgValue::Bytes(verifier_hash.clone()),
                    text(kind.as_str()),
                    i64_value(self.clock.now_unix_seconds().saturating_mul(1_000)),
                ],
            )
            .await
            .map_err(FlowStoreError::Transport)?;
        let row = rows.first().ok_or(FlowStoreError::InvalidFlow)?;
        let flow_id = Uuid::parse_str(row.required_text("flow_id")?)
            .map_err(|_| FlowStoreError::InvalidRow)?;
        let payload = self
            .key
            .open(
                kind,
                &flow_id,
                row.required_text("key_version")?,
                row.required_bytes("payload_ciphertext")?,
            )
            .map_err(|_| FlowStoreError::Crypto)?;
        Ok(PendingFlow {
            flow_id,
            user_id: row.text("user_id")?.map(str::to_owned),
            verifier_hash,
            payload,
        })
    }
}

fn flow_aad(kind: FlowKind, flow_id: &Uuid) -> Vec<u8> {
    let mut aad = Vec::with_capacity(FLOW_AAD_PREFIX.len() + 40);
    aad.extend_from_slice(FLOW_AAD_PREFIX);
    aad.extend_from_slice(kind.as_str().as_bytes());
    aad.push(b':');
    aad.extend_from_slice(flow_id.to_string().as_bytes());
    aad
}

pub(crate) fn uuid_v7<R: RandomSource>(now_ms: u64, randomness: &R) -> Result<Uuid, ()> {
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

pub(crate) fn text(value: impl ToString) -> PgValue {
    PgValue::Text(value.to_string())
}

pub(crate) fn i64_value(value: u64) -> PgValue {
    PgValue::I64(i64::try_from(value).unwrap_or(i64::MAX))
}

/// Invalid encrypted-flow key configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum FlowConfigurationError {
    /// The key version violated bounded policy.
    #[error("flow-state configuration is invalid")]
    Invalid,
}

/// Encrypted flow persistence or verification failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum FlowStoreError<E: StdError + Send + Sync + 'static> {
    /// Caller input or lifetime policy was invalid.
    #[error("flow input is invalid")]
    InvalidInput,
    /// Flow is absent, expired, consumed, or malformed.
    #[error("flow is invalid or expired")]
    InvalidFlow,
    /// Host randomness failed.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// Flow state could not be authenticated or encrypted.
    #[error("flow-state cryptography failed")]
    Crypto,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL flow transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL row decoding failed.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned malformed flow data.
    #[error("PostgreSQL returned malformed flow data")]
    InvalidRow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn key_debug_redacts_material() {
        let key = FlowSealingKey::new("flow-v1", [17; 32]).expect("valid key");
        assert!(format!("{key:?}").contains("[REDACTED]"));
    }
}
