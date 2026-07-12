//! JWT access tokens and replay-detecting refresh-token families.

use std::{error::Error as StdError, fmt};

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use base64::{
    Engine as _,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;
use zeroize::{Zeroize, Zeroizing};

use super::{
    PgRow, PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError, VerifiedSession,
};
use crate::{
    authentication::{Clock, RandomSource},
    authentication::{
        adapter_ids::{SessionId as AdapterSessionId, TenantId, UserId as AdapterUserId},
        jwt::{
            AccessTokenClaims, Algorithm, DecodingKey, EncodingKey, JwksDocument, JwksKey,
            access_token_key_id, decode_access_token, encode_access_token, jwk_from_encoding_key,
        },
    },
    context::{RequestId, SessionId},
};

const ISSUE_TOKEN_PAIR_SQL: &str = include_str!("issue_token_pair.sql");
const LOAD_REFRESH_SESSION_SQL: &str = include_str!("load_refresh_session.sql");
const ROTATE_REFRESH_TOKEN_SQL: &str = include_str!("rotate_refresh_token.sql");
const REFRESH_AAD: &[u8] = b"wasi-auth:refresh-response:v1";
const TOKEN_BYTES: usize = 32;
const NONCE_BYTES: usize = 12;
const UUID_RANDOM_BYTES: usize = 10;
const REPLAY_WINDOW_MS: u64 = 30_000;

/// Validated access/refresh lifetime policy.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TokenServiceConfig {
    issuer: String,
    audience: String,
    access_ttl_seconds: u64,
    refresh_ttl_seconds: u64,
    session_ttl_seconds: u64,
}

impl TokenServiceConfig {
    /// Constructs a bounded token policy.
    ///
    /// # Errors
    ///
    /// Rejects empty identifiers and unsafe lifetimes.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
        access_ttl_seconds: u64,
        refresh_ttl_seconds: u64,
        session_ttl_seconds: u64,
    ) -> Result<Self, TokenConfigurationError> {
        let issuer = issuer.into();
        let audience = audience.into();
        if issuer.is_empty()
            || issuer.len() > 2_048
            || issuer.chars().any(char::is_control)
            || audience.is_empty()
            || audience.len() > 256
            || audience.chars().any(char::is_control)
            || !(60..=3_600).contains(&access_ttl_seconds)
            || !(300..=90 * 24 * 60 * 60).contains(&refresh_ttl_seconds)
            || !(300..=24 * 60 * 60).contains(&session_ttl_seconds)
        {
            return Err(TokenConfigurationError::Invalid);
        }
        Ok(Self {
            issuer,
            audience,
            access_ttl_seconds,
            refresh_ttl_seconds,
            session_ttl_seconds,
        })
    }
}

/// Versioned key used to encrypt replayable refresh responses.
pub struct RefreshSealingKey {
    version: String,
    key: [u8; 32],
}

impl RefreshSealingKey {
    /// Constructs a refresh-response key.
    ///
    /// # Errors
    ///
    /// Rejects an empty or unbounded key version.
    pub fn new(version: impl Into<String>, key: [u8; 32]) -> Result<Self, TokenConfigurationError> {
        let version = version.into();
        if version.is_empty() || version.len() > 128 || version.chars().any(char::is_control) {
            return Err(TokenConfigurationError::Invalid);
        }
        Ok(Self { version, key })
    }

    fn seal(&self, nonce: [u8; NONCE_BYTES], plaintext: &[u8]) -> Result<Vec<u8>, ()> {
        let cipher = Aes256Gcm::new_from_slice(&self.key).map_err(|_| ())?;
        let ciphertext = cipher
            .encrypt(
                &Nonce::from(nonce),
                Payload {
                    msg: plaintext,
                    aad: REFRESH_AAD,
                },
            )
            .map_err(|_| ())?;
        let mut sealed = Vec::with_capacity(NONCE_BYTES + ciphertext.len());
        sealed.extend_from_slice(&nonce);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    fn open(&self, version: &str, sealed: &[u8]) -> Result<Vec<u8>, ()> {
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
                    aad: REFRESH_AAD,
                },
            )
            .map_err(|_| ())
    }
}

impl fmt::Debug for RefreshSealingKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RefreshSealingKey")
            .field("version", &self.version)
            .field("key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for RefreshSealingKey {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum KeyStatus {
    Active,
    Next,
    Retired,
    Revoked,
}

struct JwtKey {
    kid: String,
    status: KeyStatus,
    algorithm: Algorithm,
    encoding: Option<EncodingKey>,
    decoding: DecodingKey,
    public_jwk: Option<JwksKey>,
}

impl fmt::Debug for JwtKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtKey")
            .field("kid", &self.kid)
            .field("status", &self.status)
            .field("algorithm", &self.algorithm)
            .field("encoding", &self.encoding.as_ref().map(|_| "[REDACTED]"))
            .field("decoding", &"[REDACTED]")
            .field("public_jwk", &self.public_jwk)
            .finish()
    }
}

/// Validated JWT key ring with exactly one active signer.
pub struct JwtKeyRing {
    keys: Vec<JwtKey>,
    active_index: usize,
}

/// Non-secret signing-key descriptor suitable for relational lifecycle state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct JwtKeyDescriptor {
    /// Key identifier.
    pub kid: String,
    /// `ES256` or development-only `HS256`.
    pub algorithm: String,
    /// Configured initial lifecycle status.
    pub status: String,
    /// Public JWK or a non-secret symmetric-key marker.
    pub public_jwk: Value,
    /// Whether this process has private signing material for the key.
    pub has_private_material: bool,
}

impl fmt::Debug for JwtKeyRing {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("JwtKeyRing")
            .field("key_count", &self.keys.len())
            .field("active_kid", &self.keys[self.active_index].kid)
            .finish()
    }
}

impl JwtKeyRing {
    /// Creates a development-only HS256 key ring.
    ///
    /// # Errors
    ///
    /// Rejects short/default-looking secrets and malformed identifiers.
    pub fn development_hs256(
        kid: impl Into<String>,
        secret: impl Into<Vec<u8>>,
    ) -> Result<Self, TokenConfigurationError> {
        let kid = kid.into();
        let secret = Zeroizing::new(secret.into());
        if !valid_kid(&kid) || secret.len() < 32 {
            return Err(TokenConfigurationError::Invalid);
        }
        Ok(Self {
            keys: vec![JwtKey {
                kid,
                status: KeyStatus::Active,
                algorithm: Algorithm::HS256,
                encoding: Some(EncodingKey::from_secret(&secret)),
                decoding: DecodingKey::from_secret(&secret),
                public_jwk: None,
            }],
            active_index: 0,
        })
    }

    /// Parses the versioned key-ring JSON used by production configuration.
    ///
    /// Production mode permits only ES256 non-revoked keys and requires one
    /// active private key. Development may additionally use HS256.
    ///
    /// # Errors
    ///
    /// Rejects malformed JSON, keys, statuses, algorithms, or active-key sets.
    pub fn from_json(value: &str, production: bool) -> Result<Self, TokenConfigurationError> {
        let parsed: Value =
            serde_json::from_str(value).map_err(|_| TokenConfigurationError::Invalid)?;
        let entries = parsed
            .as_array()
            .or_else(|| parsed.get("keys").and_then(Value::as_array))
            .ok_or(TokenConfigurationError::Invalid)?;
        if entries.is_empty() || entries.len() > 32 {
            return Err(TokenConfigurationError::Invalid);
        }
        let mut keys = Vec::with_capacity(entries.len());
        for entry in entries {
            let kid = required_json_text(entry, "kid")?;
            if !valid_kid(&kid) || keys.iter().any(|key: &JwtKey| key.kid == kid) {
                return Err(TokenConfigurationError::Invalid);
            }
            let status = match entry
                .get("status")
                .and_then(Value::as_str)
                .unwrap_or("next")
            {
                "active" => KeyStatus::Active,
                "next" => KeyStatus::Next,
                "retired" => KeyStatus::Retired,
                "revoked" => KeyStatus::Revoked,
                _ => return Err(TokenConfigurationError::Invalid),
            };
            let algorithm = match entry.get("alg").and_then(Value::as_str).unwrap_or("ES256") {
                "ES256" => Algorithm::ES256,
                "HS256" if !production => Algorithm::HS256,
                _ => return Err(TokenConfigurationError::Invalid),
            };
            keys.push(parse_key(entry, kid, status, algorithm)?);
        }
        if production
            && keys
                .iter()
                .any(|key| key.status != KeyStatus::Revoked && key.algorithm != Algorithm::ES256)
        {
            return Err(TokenConfigurationError::Invalid);
        }
        let active = keys
            .iter()
            .enumerate()
            .filter(|(_, key)| key.status == KeyStatus::Active && key.encoding.is_some())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if active.len() != 1 {
            return Err(TokenConfigurationError::Invalid);
        }
        Ok(Self {
            keys,
            active_index: active[0],
        })
    }

    /// Returns public ES256 keys, excluding revoked material.
    #[must_use]
    pub fn jwks(&self) -> JwksDocument {
        let mut keys = self
            .keys
            .iter()
            .filter(|key| key.status != KeyStatus::Revoked)
            .filter_map(|key| key.public_jwk.clone())
            .collect::<Vec<_>>();
        keys.sort_by(|left, right| left.kid.cmp(&right.kid));
        JwksDocument { keys }
    }

    /// Returns deterministic non-secret descriptors for persistence sync.
    #[must_use]
    pub fn descriptors(&self) -> Vec<JwtKeyDescriptor> {
        let mut descriptors = self
            .keys
            .iter()
            .map(|key| JwtKeyDescriptor {
                kid: key.kid.clone(),
                algorithm: algorithm_name(key.algorithm).to_owned(),
                status: key_status_name(key.status).to_owned(),
                public_jwk: key.public_jwk.as_ref().map_or_else(
                    || {
                        serde_json::json!({
                            "kid": key.kid,
                            "kty": "oct",
                            "alg": "HS256",
                            "use": "sig"
                        })
                    },
                    |jwk| serde_json::to_value(jwk).unwrap_or(Value::Null),
                ),
                has_private_material: key.encoding.is_some(),
            })
            .collect::<Vec<_>>();
        descriptors.sort_by(|left, right| left.kid.cmp(&right.kid));
        descriptors
    }

    /// Applies authoritative relational statuses without touching key material.
    ///
    /// # Errors
    ///
    /// Rejects unknown statuses or a result without exactly one active signer.
    pub fn apply_statuses(
        &mut self,
        statuses: &[(String, String)],
    ) -> Result<(), TokenConfigurationError> {
        for (kid, status) in statuses {
            let Some(key) = self.keys.iter_mut().find(|key| &key.kid == kid) else {
                continue;
            };
            key.status = parse_key_status(status)?;
        }
        let active = self
            .keys
            .iter()
            .enumerate()
            .filter(|(_, key)| key.status == KeyStatus::Active && key.encoding.is_some())
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if active.len() != 1 {
            return Err(TokenConfigurationError::Invalid);
        }
        self.active_index = active[0];
        Ok(())
    }

    fn active(&self) -> &JwtKey {
        &self.keys[self.active_index]
    }

    fn verification(&self, kid: &str) -> Option<&JwtKey> {
        self.keys
            .iter()
            .find(|key| key.kid == kid && key.status != KeyStatus::Revoked)
    }
}

fn key_status_name(status: KeyStatus) -> &'static str {
    match status {
        KeyStatus::Active => "active",
        KeyStatus::Next => "next",
        KeyStatus::Retired => "retired",
        KeyStatus::Revoked => "revoked",
    }
}

fn parse_key_status(value: &str) -> Result<KeyStatus, TokenConfigurationError> {
    match value {
        "active" => Ok(KeyStatus::Active),
        "next" => Ok(KeyStatus::Next),
        "retired" => Ok(KeyStatus::Retired),
        "revoked" => Ok(KeyStatus::Revoked),
        _ => Err(TokenConfigurationError::Invalid),
    }
}

fn algorithm_name(algorithm: Algorithm) -> &'static str {
    match algorithm {
        Algorithm::ES256 => "ES256",
        Algorithm::HS256 => "HS256",
        _ => "unsupported",
    }
}

/// Redacted API token result.
pub struct TokenPair {
    access_token: String,
    refresh_token: String,
    expires_in_seconds: u64,
}

impl TokenPair {
    /// Takes the access token.
    pub fn into_parts(mut self) -> (String, String, u64) {
        (
            std::mem::take(&mut self.access_token),
            std::mem::take(&mut self.refresh_token),
            self.expires_in_seconds,
        )
    }
}

impl fmt::Debug for TokenPair {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("TokenPair")
            .field("access_token", &"[REDACTED]")
            .field("refresh_token", &"[REDACTED]")
            .field("expires_in_seconds", &self.expires_in_seconds)
            .finish()
    }
}

impl Drop for TokenPair {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

/// Verified token facts reloaded from the authoritative session.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct VerifiedAccessToken {
    /// User UUID.
    pub user_id: String,
    /// Selected organization UUID.
    pub organization_id: Option<String>,
    /// Session UUID.
    pub session_id: String,
    /// Current permission set.
    pub permissions: Vec<String>,
    /// Current assurance label.
    pub assurance: String,
    /// System-administrator marker.
    pub system_administrator: bool,
    /// Token issue time.
    pub issued_at_seconds: u64,
    /// Token expiry time.
    pub expires_at_seconds: u64,
}

/// PostgreSQL token-family service.
pub struct TokenService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
    keys: JwtKeyRing,
    sealing_key: RefreshSealingKey,
    config: TokenServiceConfig,
}

impl<T, C, R> TokenService<T, C, R> {
    /// Assembles the token service from validated dependencies.
    #[must_use]
    pub const fn new(
        store: PostgresAuthStore<T>,
        clock: C,
        randomness: R,
        keys: JwtKeyRing,
        sealing_key: RefreshSealingKey,
        config: TokenServiceConfig,
    ) -> Self {
        Self {
            store,
            clock,
            randomness,
            keys,
            sealing_key,
            config,
        }
    }

    /// Returns public ES256 verification keys.
    #[must_use]
    pub fn jwks(&self) -> JwksDocument {
        self.keys.jwks()
    }
}

impl<T, C, R> TokenService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Issues a new access token and refresh family for a verified session.
    ///
    /// # Errors
    ///
    /// Returns session, crypto, randomness, row, or transport failures.
    pub async fn issue(
        &self,
        session_id: &SessionId,
        request_id: &RequestId,
    ) -> Result<TokenPair, TokenServiceError<T::Error>> {
        let now = self.clock.now_unix_seconds();
        let session = self
            .store
            .load_verified_session(session_id, request_id.clone(), now)
            .await
            .map_err(|_| TokenServiceError::InvalidSession)?;
        let refresh = self.opaque_token()?;
        let pair = self.token_pair(&session, refresh, now)?;
        let refresh_hash = Sha256::digest(pair.refresh_token.as_bytes());
        let family_id = self.uuid(now.saturating_mul(1_000))?;
        let audit_id = self.uuid(now.saturating_mul(1_000))?;
        let rows = self
            .store
            .transport()
            .query(
                ISSUE_TOKEN_PAIR_SQL,
                vec![
                    text(session_id.as_str()),
                    PgValue::Bytes(refresh_hash.to_vec()),
                    text(family_id),
                    i64_value(
                        now.saturating_add(self.config.refresh_ttl_seconds)
                            .saturating_mul(1_000),
                    ),
                    i64_value(now.saturating_mul(1_000)),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await
            .map_err(TokenServiceError::Transport)?;
        if rows
            .first()
            .and_then(|row| row.required_text("outcome").ok())
            == Some("issued")
        {
            Ok(pair)
        } else {
            Err(TokenServiceError::InvalidSession)
        }
    }

    /// Rotates a refresh token with a 30-second exact-response replay window.
    /// Reuse after that window revokes the entire family and browser session.
    ///
    /// # Errors
    ///
    /// Returns invalid token, reuse, crypto, randomness, row, or transport failures.
    pub async fn refresh(
        &self,
        bound_session_id: Option<&SessionId>,
        refresh_token: &str,
        request_id: &RequestId,
    ) -> Result<TokenPair, TokenServiceError<T::Error>> {
        if refresh_token.len() < 32
            || refresh_token.len() > 512
            || refresh_token.chars().any(char::is_control)
        {
            return Err(TokenServiceError::InvalidToken);
        }
        let current_hash = Sha256::digest(refresh_token.as_bytes());
        let session_rows = self
            .store
            .transport()
            .query(
                LOAD_REFRESH_SESSION_SQL,
                vec![PgValue::Bytes(current_hash.to_vec())],
            )
            .await
            .map_err(TokenServiceError::Transport)?;
        let session_id = SessionId::new(
            session_rows
                .first()
                .ok_or(TokenServiceError::InvalidToken)?
                .required_text("session_id")?
                .to_owned(),
        )
        .map_err(|_| TokenServiceError::InvalidToken)?;
        if bound_session_id.is_some_and(|bound| bound != &session_id) {
            return Err(TokenServiceError::InvalidToken);
        }
        let now = self.clock.now_unix_seconds();
        let session = self
            .store
            .load_verified_session(&session_id, request_id.clone(), now)
            .await
            .map_err(|_| TokenServiceError::InvalidToken)?;
        let next_refresh = self.opaque_token()?;
        let pair = self.token_pair(&session, next_refresh, now)?;
        let serialized = serde_json::to_vec(&RefreshResponse::from_pair(&pair))
            .map_err(|_| TokenServiceError::Crypto)?;
        let mut nonce = [0_u8; NONCE_BYTES];
        self.randomness
            .fill_bytes(&mut nonce)
            .map_err(|_| TokenServiceError::RandomnessUnavailable)?;
        let sealed = self
            .sealing_key
            .seal(nonce, &serialized)
            .map_err(|_| TokenServiceError::Crypto)?;
        let next_hash = Sha256::digest(pair.refresh_token.as_bytes());
        let now_ms = now.saturating_mul(1_000);
        let rotation_audit = self.uuid(now_ms)?;
        let reuse_audit = self.uuid(now_ms)?;
        let rows = self
            .store
            .transport()
            .query(
                ROTATE_REFRESH_TOKEN_SQL,
                vec![
                    PgValue::Bytes(current_hash.to_vec()),
                    bound_session_id.map_or(PgValue::Null, |session| text(session.as_str())),
                    PgValue::Bytes(next_hash.to_vec()),
                    text(&self.sealing_key.version),
                    PgValue::Bytes(sealed),
                    i64_value(now_ms.saturating_add(REPLAY_WINDOW_MS)),
                    i64_value(now_ms),
                    i64_value(
                        now.saturating_add(self.config.refresh_ttl_seconds)
                            .saturating_mul(1_000),
                    ),
                    text(rotation_audit),
                    text(reuse_audit),
                    text(request_id.as_str()),
                    i64_value(
                        now.saturating_add(self.config.session_ttl_seconds)
                            .saturating_mul(1_000),
                    ),
                ],
            )
            .await
            .map_err(TokenServiceError::Transport)?;
        let row = rows.first().ok_or(TokenServiceError::InvalidToken)?;
        match row.required_text("outcome")? {
            "rotated" => Ok(pair),
            "replayed" => self.decode_replay(row),
            "reuse_detected" => Err(TokenServiceError::ReuseDetected),
            _ => Err(TokenServiceError::InvalidToken),
        }
    }

    /// Verifies signature/claims then replaces token permissions and account
    /// state with one authoritative session load.
    ///
    /// # Errors
    ///
    /// Returns invalid/expired token or current-session persistence failures.
    pub async fn verify(
        &self,
        token: &str,
        request_id: &RequestId,
    ) -> Result<VerifiedAccessToken, TokenServiceError<T::Error>> {
        let kid = access_token_key_id(token).map_err(|_| TokenServiceError::InvalidToken)?;
        let key = self
            .keys
            .verification(&kid)
            .ok_or(TokenServiceError::InvalidToken)?;
        let claims = decode_access_token(
            token,
            &key.decoding,
            &self.config.issuer,
            &self.config.audience,
            &[key.algorithm],
        )
        .map_err(|_| TokenServiceError::InvalidToken)?;
        let session_id = claims
            .session_id
            .as_ref()
            .map(|session| SessionId::new(session.as_str().to_owned()))
            .transpose()
            .map_err(|_| TokenServiceError::InvalidToken)?
            .ok_or(TokenServiceError::InvalidToken)?;
        let session = self
            .store
            .load_verified_session(
                &session_id,
                request_id.clone(),
                self.clock.now_unix_seconds(),
            )
            .await
            .map_err(|_| TokenServiceError::InvalidToken)?;
        let context = session.context();
        if claims.sub != context.auth().principal().user_id().as_str()
            || claims.tenant_id.as_ref().map(|tenant| tenant.as_str())
                != context
                    .auth()
                    .organization_id()
                    .map(|organization| organization.as_str())
        {
            return Err(TokenServiceError::InvalidToken);
        }
        Ok(VerifiedAccessToken {
            user_id: claims.sub,
            organization_id: context.auth().organization_id().map(ToString::to_string),
            session_id: session_id.into_string(),
            permissions: context
                .authorization()
                .permissions()
                .map(str::to_owned)
                .collect(),
            assurance: assurance_name(context.auth().assurance()).to_owned(),
            system_administrator: context.auth().principal().is_system_administrator(),
            issued_at_seconds: claims.iat,
            expires_at_seconds: claims.exp,
        })
    }

    fn token_pair(
        &self,
        session: &VerifiedSession,
        refresh_token: String,
        now: u64,
    ) -> Result<TokenPair, TokenServiceError<T::Error>> {
        let context = session.context();
        let expires_at = now
            .saturating_add(self.config.access_ttl_seconds)
            .min(context.auth().expires_at_unix_seconds());
        if expires_at <= now {
            return Err(TokenServiceError::InvalidSession);
        }
        let active = self.keys.active();
        let mut claims = AccessTokenClaims::for_user(
            self.config.issuer.clone(),
            AdapterUserId::from(context.auth().principal().user_id().as_str()),
            vec![self.config.audience.clone()],
            expires_at,
            now,
            self.uuid(now.saturating_mul(1_000))?.to_string(),
        );
        claims.tenant_id = context
            .auth()
            .organization_id()
            .map(|organization| TenantId::from(organization.as_str()));
        claims.session_id = Some(AdapterSessionId::from(context.auth().session_id().as_str()));
        claims.roles = context
            .authorization()
            .role_ids()
            .map(ToString::to_string)
            .collect();
        claims.scope = context
            .authorization()
            .permissions()
            .map(str::to_owned)
            .collect();
        claims.auth_time = Some(context.auth().issued_at_unix_seconds());
        let access_token = encode_access_token(
            &claims,
            active.encoding.as_ref().ok_or(TokenServiceError::Crypto)?,
            active.algorithm,
            Some(&active.kid),
        )
        .map_err(|_| TokenServiceError::Crypto)?;
        Ok(TokenPair {
            access_token,
            refresh_token,
            expires_in_seconds: expires_at.saturating_sub(now),
        })
    }

    fn decode_replay(&self, row: &PgRow) -> Result<TokenPair, TokenServiceError<T::Error>> {
        let plaintext = Zeroizing::new(
            self.sealing_key
                .open(
                    row.required_text("response_key_version")?,
                    row.required_bytes("response_ciphertext")?,
                )
                .map_err(|_| TokenServiceError::Crypto)?,
        );
        let response = serde_json::from_slice::<RefreshResponse>(&plaintext)
            .map_err(|_| TokenServiceError::Crypto)?;
        Ok(response.into_pair())
    }

    fn opaque_token(&self) -> Result<String, TokenServiceError<T::Error>> {
        let mut bytes = [0_u8; TOKEN_BYTES];
        self.randomness
            .fill_bytes(&mut bytes)
            .map_err(|_| TokenServiceError::RandomnessUnavailable)?;
        Ok(URL_SAFE_NO_PAD.encode(bytes))
    }

    fn uuid(&self, now_ms: u64) -> Result<Uuid, TokenServiceError<T::Error>> {
        uuid_v7(now_ms, &self.randomness).map_err(|_| TokenServiceError::RandomnessUnavailable)
    }
}

#[derive(Deserialize, Serialize)]
struct RefreshResponse {
    access_token: String,
    refresh_token: String,
    expires_in_seconds: u64,
}

impl RefreshResponse {
    fn from_pair(pair: &TokenPair) -> Self {
        Self {
            access_token: pair.access_token.clone(),
            refresh_token: pair.refresh_token.clone(),
            expires_in_seconds: pair.expires_in_seconds,
        }
    }

    fn into_pair(mut self) -> TokenPair {
        TokenPair {
            access_token: std::mem::take(&mut self.access_token),
            refresh_token: std::mem::take(&mut self.refresh_token),
            expires_in_seconds: self.expires_in_seconds,
        }
    }
}

impl Drop for RefreshResponse {
    fn drop(&mut self) {
        self.access_token.zeroize();
        self.refresh_token.zeroize();
    }
}

fn parse_key(
    value: &Value,
    kid: String,
    status: KeyStatus,
    algorithm: Algorithm,
) -> Result<JwtKey, TokenConfigurationError> {
    match algorithm {
        Algorithm::HS256 => {
            let secret = Zeroizing::new(required_json_text(value, "secret")?.into_bytes());
            if secret.len() < 32 {
                return Err(TokenConfigurationError::Invalid);
            }
            Ok(JwtKey {
                kid,
                status,
                algorithm,
                encoding: Some(EncodingKey::from_secret(&secret)),
                decoding: DecodingKey::from_secret(&secret),
                public_jwk: None,
            })
        }
        Algorithm::ES256 => {
            let private_der = value
                .get("private_key_der_base64")
                .and_then(Value::as_str)
                .map(decode_base64)
                .transpose()?;
            let encoding = private_der
                .as_ref()
                .map(|bytes| EncodingKey::from_ec_der(bytes));
            let mut public_jwk = value
                .get("public_jwks_json")
                .or_else(|| value.get("public_jwk_json"))
                .and_then(Value::as_str)
                .map(parse_jwk)
                .transpose()?;
            if public_jwk.is_none() {
                let encoding = encoding.as_ref().ok_or(TokenConfigurationError::Invalid)?;
                let value = serde_json::to_value(
                    jwk_from_encoding_key(encoding, Algorithm::ES256)
                        .map_err(|_| TokenConfigurationError::Invalid)?,
                )
                .map_err(|_| TokenConfigurationError::Invalid)?;
                public_jwk = Some(
                    serde_json::from_value(value).map_err(|_| TokenConfigurationError::Invalid)?,
                );
            }
            let mut public_jwk = public_jwk.ok_or(TokenConfigurationError::Invalid)?;
            public_jwk.kid = kid.clone();
            public_jwk.alg = "ES256".to_owned();
            public_jwk.use_ = "sig".to_owned();
            let decoding = decoding_key(&public_jwk)?;
            if status == KeyStatus::Active && encoding.is_none() {
                return Err(TokenConfigurationError::Invalid);
            }
            Ok(JwtKey {
                kid,
                status,
                algorithm,
                encoding,
                decoding,
                public_jwk: Some(public_jwk),
            })
        }
        _ => Err(TokenConfigurationError::Invalid),
    }
}

fn parse_jwk(value: &str) -> Result<JwksKey, TokenConfigurationError> {
    let value: Value = serde_json::from_str(value).map_err(|_| TokenConfigurationError::Invalid)?;
    if let Some(keys) = value.get("keys").and_then(Value::as_array) {
        if keys.len() != 1 {
            return Err(TokenConfigurationError::Invalid);
        }
        serde_json::from_value(keys[0].clone()).map_err(|_| TokenConfigurationError::Invalid)
    } else {
        serde_json::from_value(value).map_err(|_| TokenConfigurationError::Invalid)
    }
}

fn decoding_key(key: &JwksKey) -> Result<DecodingKey, TokenConfigurationError> {
    if key.kty != "EC" || (!key.alg.is_empty() && key.alg != "ES256") {
        return Err(TokenConfigurationError::Invalid);
    }
    let x = key
        .public_parameters
        .get("x")
        .ok_or(TokenConfigurationError::Invalid)?;
    let y = key
        .public_parameters
        .get("y")
        .ok_or(TokenConfigurationError::Invalid)?;
    DecodingKey::from_ec_components(x, y).map_err(|_| TokenConfigurationError::Invalid)
}

fn required_json_text(value: &Value, name: &str) -> Result<String, TokenConfigurationError> {
    value
        .get(name)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.chars().any(char::is_control))
        .map(str::to_owned)
        .ok_or(TokenConfigurationError::Invalid)
}

fn decode_base64(value: &str) -> Result<Zeroizing<Vec<u8>>, TokenConfigurationError> {
    let compact = value.split_whitespace().collect::<String>();
    STANDARD
        .decode(compact.as_bytes())
        .or_else(|_| URL_SAFE_NO_PAD.decode(compact.as_bytes()))
        .map(Zeroizing::new)
        .map_err(|_| TokenConfigurationError::Invalid)
}

fn valid_kid(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}

fn assurance_name(value: crate::context::AuthenticationAssurance) -> &'static str {
    match value {
        crate::context::AuthenticationAssurance::Aal1 => "aal1",
        crate::context::AuthenticationAssurance::Aal2 => "aal2",
    }
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

/// Invalid JWT or refresh cryptographic configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TokenConfigurationError {
    /// Configuration violated a bounded production contract.
    #[error("token service configuration is invalid")]
    Invalid,
}

/// Token issue, rotation, or verification failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TokenServiceError<E: StdError + Send + Sync + 'static> {
    /// Session is missing, expired, revoked, stale, or disabled.
    #[error("session is invalid")]
    InvalidSession,
    /// Access or refresh token is malformed, expired, or unknown.
    #[error("token is invalid")]
    InvalidToken,
    /// A rotated refresh token was reused outside its retry window.
    #[error("refresh token reuse detected; token family revoked")]
    ReuseDetected,
    /// Host randomness failed.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// JWT or refresh-response cryptography failed.
    #[error("token cryptography failed")]
    Crypto,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL token transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL row decoding failed.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn development_key_requires_real_entropy() {
        assert!(JwtKeyRing::development_hs256("dev", vec![1; 31]).is_err());
        assert!(JwtKeyRing::development_hs256("dev", vec![1; 32]).is_ok());
    }

    #[test]
    fn configured_next_hs256_key_retains_material_for_promotion() {
        let mut ring = JwtKeyRing::from_json(
            &serde_json::json!({
                "keys": [
                    {
                        "kid": "current",
                        "status": "active",
                        "alg": "HS256",
                        "secret": "current-development-signing-secret"
                    },
                    {
                        "kid": "replacement",
                        "status": "next",
                        "alg": "HS256",
                        "secret": "replacement-development-signing-secret"
                    }
                ]
            })
            .to_string(),
            false,
        )
        .expect("development key ring should be valid");

        assert!(
            ring.descriptors()
                .iter()
                .all(|key| key.has_private_material)
        );
        ring.apply_statuses(&[
            ("current".to_owned(), "retired".to_owned()),
            ("replacement".to_owned(), "active".to_owned()),
        ])
        .expect("next key should be promotable without reloading secrets");
        assert_eq!(ring.active().kid, "replacement");
    }

    #[test]
    fn token_pair_debug_is_redacted() {
        let pair = TokenPair {
            access_token: "access-secret".to_owned(),
            refresh_token: "refresh-secret".to_owned(),
            expires_in_seconds: 60,
        };
        let debug = format!("{pair:?}");
        assert!(!debug.contains("access-secret"));
        assert!(!debug.contains("refresh-secret"));
    }
}
