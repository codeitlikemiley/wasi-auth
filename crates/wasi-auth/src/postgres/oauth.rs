//! OAuth state, PKCE, identity linking, and session workflows.

use std::{error::Error as StdError, fmt};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use thiserror::Error;
use zeroize::Zeroize;

use super::{PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};
use crate::{
    authentication::{Clock, RandomSource},
    context::{RequestId, SessionId},
};

use super::flows::{
    EncryptedFlowStore, FlowKind, FlowSealingKey, FlowStoreError, PendingFlow, i64_value, text,
    uuid_v7,
};

const COMPLETE_OAUTH_IDENTITY_SQL: &str = include_str!("complete_oauth_identity.sql");
const VALIDATE_APPLICATION_REDIRECT_SQL: &str = include_str!("validate_application_redirect.sql");
const LIST_OAUTH_PROVIDERS_SQL: &str = include_str!("list_oauth_providers.sql");
const GET_OAUTH_PROVIDER_SQL: &str = include_str!("get_oauth_provider.sql");
const SAVE_OAUTH_PROVIDER_SQL: &str = include_str!("save_oauth_provider.sql");
const REPLACE_APPLICATION_REDIRECTS_SQL: &str = include_str!("replace_application_redirects.sql");
const RANDOM_SECRET_BYTES: usize = 32;
const MAX_PROFILE_BYTES: usize = 16 * 1_024;

/// Validated OAuth flow and session lifetime policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct OAuthServiceConfig {
    flow_ttl_seconds: u64,
    session_ttl_seconds: u64,
}

impl OAuthServiceConfig {
    /// Constructs bounded OAuth lifetimes.
    ///
    /// # Errors
    ///
    /// Rejects state lifetimes outside 1–15 minutes or session lifetimes
    /// outside 5 minutes–24 hours.
    pub fn new(
        flow_ttl_seconds: u64,
        session_ttl_seconds: u64,
    ) -> Result<Self, OAuthConfigurationError> {
        if !(60..=15 * 60).contains(&flow_ttl_seconds)
            || !(5 * 60..=24 * 60 * 60).contains(&session_ttl_seconds)
        {
            return Err(OAuthConfigurationError::Invalid);
        }
        Ok(Self {
            flow_ttl_seconds,
            session_ttl_seconds,
        })
    }
}

/// One-time values needed to construct an OAuth authorization URL.
pub struct OAuthStart {
    state: String,
    nonce: String,
    pkce_challenge: String,
}

impl OAuthStart {
    /// Takes state, nonce, and the S256 PKCE challenge.
    #[must_use]
    pub fn into_parts(mut self) -> (String, String, String) {
        (
            std::mem::take(&mut self.state),
            std::mem::take(&mut self.nonce),
            std::mem::take(&mut self.pkce_challenge),
        )
    }
}

impl fmt::Debug for OAuthStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("OAuthStart")
            .field("state", &"[REDACTED]")
            .field("nonce", &"[REDACTED]")
            .field("pkce_challenge", &self.pkce_challenge)
            .finish()
    }
}

impl Drop for OAuthStart {
    fn drop(&mut self) {
        self.state.zeroize();
        self.nonce.zeroize();
    }
}

/// Loaded, authenticated callback state that has not yet been consumed.
pub struct PendingOAuthFlow {
    flow: PendingFlow,
    payload: StoredOAuthPayload,
}

impl PendingOAuthFlow {
    /// Returns the provider identifier bound to this state.
    #[must_use]
    pub fn provider_id(&self) -> &str {
        &self.payload.provider_id
    }

    /// Returns the validated local redirect path.
    #[must_use]
    pub fn redirect_path(&self) -> &str {
        &self.payload.redirect_path
    }

    /// Returns the OIDC nonce for ID-token verification.
    #[must_use]
    pub fn nonce(&self) -> &str {
        &self.payload.nonce
    }

    /// Returns the PKCE verifier for the token exchange.
    #[must_use]
    pub fn pkce_verifier(&self) -> &str {
        &self.payload.pkce_verifier
    }

    /// Returns an opaque identifier useful only for development fixtures.
    #[must_use]
    pub fn development_subject(&self) -> String {
        self.flow.flow_id.to_string()
    }
}

impl fmt::Debug for PendingOAuthFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PendingOAuthFlow")
            .field("flow", &self.flow)
            .field("provider_id", &self.payload.provider_id)
            .field("redirect_path", &self.payload.redirect_path)
            .field("nonce", &"[REDACTED]")
            .field("pkce_verifier", &"[REDACTED]")
            .finish()
    }
}

/// Provider identity accepted after token, issuer, audience, signature, and
/// nonce verification by the runtime presenter.
#[derive(Clone, Debug)]
pub struct VerifiedOAuthIdentity {
    /// Provider configuration identifier.
    pub provider_id: String,
    /// Stable provider subject claim.
    pub provider_subject: String,
    /// Provider email claim, when available.
    pub email: Option<String>,
    /// Whether the provider explicitly verified the email claim.
    pub email_verified: bool,
    /// Bounded profile metadata safe for a read model.
    pub profile: Value,
}

/// Session created by successful OAuth identity completion.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthCompletion {
    /// New browser/API session identifier.
    pub session_id: SessionId,
    /// Global user UUID.
    pub user_id: String,
    /// Authoritative primary email.
    pub primary_email: String,
    /// Session expiry in milliseconds since Unix epoch.
    pub expires_at_ms: u64,
    /// Validated post-login local redirect path.
    pub redirect_path: String,
}

/// Non-secret OAuth provider configuration exposed to presenters.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OAuthProviderRecord {
    /// Canonical provider identifier.
    pub provider_id: String,
    /// User-facing provider name.
    pub display_name: String,
    /// Whether login may be offered when runtime credentials also exist.
    pub enabled: bool,
    /// Configured OAuth scopes.
    pub scopes: Vec<String>,
    /// Non-secret claim mapping metadata.
    pub claim_mapping: Value,
}

#[derive(Serialize, Deserialize)]
struct StoredOAuthPayload {
    provider_id: String,
    redirect_path: String,
    nonce: String,
    pkce_verifier: String,
}

impl Drop for StoredOAuthPayload {
    fn drop(&mut self) {
        self.nonce.zeroize();
        self.pkce_verifier.zeroize();
    }
}

/// PostgreSQL OAuth workflow service.
pub struct OAuthFlowService<T, C, R> {
    flows: EncryptedFlowStore<T, C, R>,
    config: OAuthServiceConfig,
}

impl<T, C, R> OAuthFlowService<T, C, R> {
    /// Assembles the OAuth service from validated dependencies.
    #[must_use]
    pub const fn new(
        store: PostgresAuthStore<T>,
        clock: C,
        randomness: R,
        sealing_key: FlowSealingKey,
        config: OAuthServiceConfig,
    ) -> Self {
        Self {
            flows: EncryptedFlowStore::new(store, clock, randomness, sealing_key),
            config,
        }
    }
}

impl<T, C, R> OAuthFlowService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Creates independent state, nonce, and PKCE S256 values.
    ///
    /// # Errors
    ///
    /// Returns validation, serialization, randomness, crypto, or transport failures.
    pub async fn start(
        &self,
        provider_id: &str,
        redirect_path: &str,
    ) -> Result<OAuthStart, OAuthServiceError<T::Error>> {
        if !valid_provider_id(provider_id) || !safe_redirect_path(redirect_path) {
            return Err(OAuthServiceError::InvalidInput);
        }
        let allowed = self
            .flows
            .transport()
            .query(VALIDATE_APPLICATION_REDIRECT_SQL, vec![text(redirect_path)])
            .await
            .map_err(OAuthServiceError::Transport)?;
        if allowed.is_empty() {
            return Err(OAuthServiceError::InvalidInput);
        }
        let nonce = self.random_secret()?;
        let pkce_verifier = self.random_secret()?;
        let pkce_challenge = URL_SAFE_NO_PAD.encode(Sha256::digest(pkce_verifier.as_bytes()));
        let payload = serde_json::to_vec(&StoredOAuthPayload {
            provider_id: provider_id.to_owned(),
            redirect_path: redirect_path.to_owned(),
            nonce: nonce.clone(),
            pkce_verifier,
        })
        .map_err(|_| OAuthServiceError::Serialization)?;
        let state = self
            .flows
            .create(
                FlowKind::OAuth,
                None,
                &payload,
                self.config.flow_ttl_seconds,
            )
            .await?;
        Ok(OAuthStart {
            state,
            nonce,
            pkce_challenge,
        })
    }

    /// Authenticates callback state without consuming it. The caller may safely
    /// perform the provider token exchange before committing the identity.
    ///
    /// # Errors
    ///
    /// Returns invalid, expired, tampered, or provider-mismatched state.
    pub async fn load_callback(
        &self,
        provider_id: &str,
        state: &str,
    ) -> Result<PendingOAuthFlow, OAuthServiceError<T::Error>> {
        if !valid_provider_id(provider_id) {
            return Err(OAuthServiceError::InvalidInput);
        }
        let mut flow = self.flows.load(FlowKind::OAuth, state).await?;
        let payload = serde_json::from_slice::<StoredOAuthPayload>(&flow.payload)
            .map_err(|_| OAuthServiceError::Serialization)?;
        flow.payload.zeroize();
        if payload.provider_id != provider_id || !safe_redirect_path(&payload.redirect_path) {
            return Err(OAuthServiceError::InvalidFlow);
        }
        Ok(PendingOAuthFlow { flow, payload })
    }

    /// Atomically consumes callback state, links the verified provider identity,
    /// creates or resolves the global user, creates a session, and audits login.
    ///
    /// # Errors
    ///
    /// Returns provider mismatch, unverified identity, replay, account-state,
    /// row, randomness, or transport failures.
    pub async fn complete(
        &self,
        pending: PendingOAuthFlow,
        identity: VerifiedOAuthIdentity,
        request_id: &RequestId,
    ) -> Result<OAuthCompletion, OAuthServiceError<T::Error>> {
        if identity.provider_id != pending.payload.provider_id
            || !bounded_subject(&identity.provider_subject)
        {
            return Err(OAuthServiceError::InvalidIdentity);
        }
        let normalized_email = match identity.email.as_deref() {
            Some(email) if identity.email_verified => {
                Some(normalize_email(email).map_err(|()| OAuthServiceError::InvalidIdentity)?)
            }
            _ => None,
        };
        let profile =
            serde_json::to_vec(&identity.profile).map_err(|_| OAuthServiceError::Serialization)?;
        if profile.len() > MAX_PROFILE_BYTES {
            return Err(OAuthServiceError::InvalidIdentity);
        }
        let now_ms = self.flows.now_unix_seconds().saturating_mul(1_000);
        let new_user_id = self
            .flows
            .uuid(now_ms)
            .map_err(|_| OAuthServiceError::RandomnessUnavailable)?;
        let session_id = self
            .flows
            .uuid(now_ms)
            .map_err(|_| OAuthServiceError::RandomnessUnavailable)?;
        let audit_id = self
            .flows
            .uuid(now_ms)
            .map_err(|_| OAuthServiceError::RandomnessUnavailable)?;
        let rows = self
            .flows
            .transport()
            .query(
                COMPLETE_OAUTH_IDENTITY_SQL,
                vec![
                    PgValue::Bytes(pending.flow.verifier_hash.clone()),
                    text(pending.flow.flow_id),
                    text(&identity.provider_id),
                    text(&identity.provider_subject),
                    normalized_email.as_ref().map_or(PgValue::Null, text),
                    normalized_email.as_ref().map_or(PgValue::Null, text),
                    PgValue::Json(identity.profile),
                    text(new_user_id),
                    text(session_id),
                    i64_value(
                        now_ms
                            .saturating_add(self.config.session_ttl_seconds.saturating_mul(1_000)),
                    ),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await
            .map_err(OAuthServiceError::Transport)?;
        let row = rows.first().ok_or(OAuthServiceError::InvalidFlow)?;
        match row.required_text("outcome")? {
            "completed" => Ok(OAuthCompletion {
                session_id: SessionId::new(row.required_text("session_id")?.to_owned())
                    .map_err(|_| OAuthServiceError::InvalidRow)?,
                user_id: row.required_text("user_id")?.to_owned(),
                primary_email: row.required_text("primary_email")?.to_owned(),
                expires_at_ms: u64::try_from(row.required_i64("expires_at_ms")?)
                    .map_err(|_| OAuthServiceError::InvalidRow)?,
                redirect_path: pending.payload.redirect_path.clone(),
            }),
            "account_unavailable" => Err(OAuthServiceError::AccountUnavailable),
            _ => Err(OAuthServiceError::InvalidRow),
        }
    }

    fn random_secret(&self) -> Result<String, OAuthServiceError<T::Error>> {
        let mut bytes = [0_u8; RANDOM_SECRET_BYTES];
        self.flows
            .fill_bytes(&mut bytes)
            .map_err(|_| OAuthServiceError::RandomnessUnavailable)?;
        let result = URL_SAFE_NO_PAD.encode(bytes);
        bytes.zeroize();
        Ok(result)
    }
}

/// PostgreSQL OAuth provider administration service.
pub struct OAuthProviderService<T, C, R> {
    store: PostgresAuthStore<T>,
    clock: C,
    randomness: R,
}

impl<T, C, R> OAuthProviderService<T, C, R> {
    /// Assembles provider administration from persistence, time, and randomness.
    #[must_use]
    pub const fn new(store: PostgresAuthStore<T>, clock: C, randomness: R) -> Self {
        Self {
            store,
            clock,
            randomness,
        }
    }
}

impl<T, C, R> OAuthProviderService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Lists configured providers without secret references.
    ///
    /// # Errors
    ///
    /// Returns malformed-row or PostgreSQL transport failures.
    pub async fn list(
        &self,
    ) -> Result<Vec<OAuthProviderRecord>, OAuthProviderServiceError<T::Error>> {
        self.store
            .transport()
            .query(LIST_OAUTH_PROVIDERS_SQL, Vec::new())
            .await
            .map_err(OAuthProviderServiceError::Transport)?
            .iter()
            .map(provider_from_row)
            .collect()
    }

    /// Finds one configured provider without revealing secret references.
    ///
    /// # Errors
    ///
    /// Returns invalid provider, malformed-row, or transport failures.
    pub async fn get(
        &self,
        provider_id: &str,
    ) -> Result<Option<OAuthProviderRecord>, OAuthProviderServiceError<T::Error>> {
        if !valid_provider_id(provider_id) {
            return Err(OAuthProviderServiceError::InvalidInput);
        }
        self.store
            .transport()
            .query(GET_OAUTH_PROVIDER_SQL, vec![text(provider_id)])
            .await
            .map_err(OAuthProviderServiceError::Transport)?
            .first()
            .map(provider_from_row)
            .transpose()
    }

    /// Updates provider visibility under a live AAL2 system-admin session and
    /// writes the matching audit record in the same PostgreSQL statement.
    ///
    /// # Errors
    ///
    /// Returns invalid input, admin-session, randomness, row, or transport failures.
    pub async fn save(
        &self,
        session_id: &SessionId,
        provider_id: &str,
        display_name: &str,
        enabled: bool,
        request_id: &RequestId,
    ) -> Result<OAuthProviderRecord, OAuthProviderServiceError<T::Error>> {
        if !valid_provider_id(provider_id)
            || display_name.trim().is_empty()
            || display_name.len() > 128
            || display_name.chars().any(char::is_control)
        {
            return Err(OAuthProviderServiceError::InvalidInput);
        }
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| OAuthProviderServiceError::RandomnessUnavailable)?;
        let rows = self
            .store
            .transport()
            .query(
                SAVE_OAUTH_PROVIDER_SQL,
                vec![
                    text(session_id.as_str()),
                    text(provider_id),
                    text(display_name.trim()),
                    PgValue::Bool(enabled),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await
            .map_err(OAuthProviderServiceError::Transport)?;
        rows.first()
            .ok_or(OAuthProviderServiceError::InvalidAdminSession)
            .and_then(provider_from_row)
    }

    /// Atomically replaces the exact local post-login redirect allowlist under
    /// a live AAL2 system-admin session and records one audit event.
    ///
    /// # Errors
    ///
    /// Returns invalid paths, admin-session, randomness, row, or transport failures.
    pub async fn replace_redirects(
        &self,
        session_id: &SessionId,
        redirects: &[String],
        request_id: &RequestId,
    ) -> Result<Vec<String>, OAuthProviderServiceError<T::Error>> {
        if redirects.is_empty()
            || redirects.len() > 100
            || redirects.iter().any(|path| !safe_redirect_path(path))
        {
            return Err(OAuthProviderServiceError::InvalidInput);
        }
        let mut normalized = redirects.to_vec();
        normalized.sort();
        normalized.dedup();
        let now_ms = self.clock.now_unix_seconds().saturating_mul(1_000);
        let audit_id = uuid_v7(now_ms, &self.randomness)
            .map_err(|_| OAuthProviderServiceError::RandomnessUnavailable)?;
        let rows = self
            .store
            .transport()
            .query(
                REPLACE_APPLICATION_REDIRECTS_SQL,
                vec![
                    text(session_id.as_str()),
                    PgValue::Json(Value::Array(
                        normalized.iter().cloned().map(Value::String).collect(),
                    )),
                    i64_value(now_ms),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await
            .map_err(OAuthProviderServiceError::Transport)?;
        if rows.len() != normalized.len() {
            return Err(OAuthProviderServiceError::InvalidAdminSession);
        }
        rows.iter()
            .map(|row| {
                row.required_text("redirect_path")
                    .map(str::to_owned)
                    .map_err(OAuthProviderServiceError::Row)
            })
            .collect()
    }
}

fn provider_from_row<E>(
    row: &super::PgRow,
) -> Result<OAuthProviderRecord, OAuthProviderServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let scopes = row
        .json("scopes")?
        .and_then(Value::as_array)
        .ok_or(OAuthProviderServiceError::InvalidRow)?
        .iter()
        .map(|value| {
            value
                .as_str()
                .filter(|scope| scope.len() <= 256 && !scope.chars().any(char::is_control))
                .map(str::to_owned)
                .ok_or(OAuthProviderServiceError::InvalidRow)
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(OAuthProviderRecord {
        provider_id: row.required_text("provider_id")?.to_owned(),
        display_name: row.required_text("display_name")?.to_owned(),
        enabled: row
            .bool("enabled")?
            .ok_or(OAuthProviderServiceError::InvalidRow)?,
        scopes,
        claim_mapping: row
            .json("claim_mapping")?
            .cloned()
            .ok_or(OAuthProviderServiceError::InvalidRow)?,
    })
}

fn valid_provider_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
        })
}

fn safe_redirect_path(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= 2_048
        && !value.chars().any(char::is_control)
}

fn bounded_subject(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 1_024 && !value.chars().any(char::is_control)
}

fn normalize_email(value: &str) -> Result<String, ()> {
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() > 320
        || normalized.starts_with('@')
        || normalized.ends_with('@')
        || normalized.matches('@').count() != 1
        || normalized.chars().any(char::is_control)
    {
        return Err(());
    }
    Ok(normalized)
}

/// Invalid OAuth service policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum OAuthConfigurationError {
    /// A configured lifetime was outside production bounds.
    #[error("OAuth configuration is invalid")]
    Invalid,
}

/// OAuth state, identity, or persistence failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OAuthServiceError<E: StdError + Send + Sync + 'static> {
    /// Provider, redirect, or request data was invalid.
    #[error("OAuth input is invalid")]
    InvalidInput,
    /// State was absent, expired, consumed, tampered, or provider-mismatched.
    #[error("OAuth state is invalid or expired")]
    InvalidFlow,
    /// Provider identity was malformed or lacked a verified linking claim.
    #[error("OAuth identity is invalid")]
    InvalidIdentity,
    /// The linked account is disabled or otherwise unavailable.
    #[error("OAuth account is unavailable")]
    AccountUnavailable,
    /// Host randomness failed.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// Secret state could not be encoded.
    #[error("OAuth state serialization failed")]
    Serialization,
    /// Shared encrypted-flow handling failed.
    #[error(transparent)]
    Flow(#[from] FlowStoreError<E>),
    /// PostgreSQL transport failed.
    #[error("PostgreSQL OAuth transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL row decoding failed.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned malformed OAuth data.
    #[error("PostgreSQL returned malformed OAuth data")]
    InvalidRow,
}

/// OAuth provider administration failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum OAuthProviderServiceError<E: StdError + Send + Sync + 'static> {
    /// Provider identifier or display name was invalid.
    #[error("OAuth provider input is invalid")]
    InvalidInput,
    /// Session was not a live AAL2 system-administrator session.
    #[error("OAuth provider administration requires an AAL2 system administrator")]
    InvalidAdminSession,
    /// Host randomness failed.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// PostgreSQL transport failed.
    #[error("PostgreSQL OAuth provider transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL row decoding failed.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned malformed provider data.
    #[error("PostgreSQL returned malformed OAuth provider data")]
    InvalidRow,
}
