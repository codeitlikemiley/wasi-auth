//! WebAuthn registration and authentication over encrypted one-time flows.

use std::{error::Error as StdError, fmt};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;
use zeroize::Zeroize;

use super::{PgRow, PgValue, PostgresAuthStore, PostgresTransport, RowDecodeError};
use crate::{
    authentication::passkeys::{
        Attachment, AuthenticationResponse, AuthenticationState, CredentialId, PasskeyCredential,
        RegistrationResponse, RegistrationState, Webauthn,
    },
    authentication::{Clock, RandomSource},
    context::{RequestId, SessionId},
};

use super::flows::{
    EncryptedFlowStore, FlowKind, FlowSealingKey, FlowStoreError, PendingFlow, i64_value, text,
};

const LOAD_PASSKEYS_FOR_USER_SQL: &str = include_str!("load_passkeys_for_user.sql");
const LOAD_PASSKEYS_FOR_EMAIL_SQL: &str = include_str!("load_passkeys_for_email.sql");
const LOAD_PASSKEY_CREDENTIAL_SQL: &str = include_str!("load_passkey_credential.sql");
const COMPLETE_PASSKEY_REGISTRATION_SQL: &str = include_str!("complete_passkey_registration.sql");
const COMPLETE_PASSKEY_AUTHENTICATION_SQL: &str =
    include_str!("complete_passkey_authentication.sql");
const MAX_CREDENTIAL_RESPONSE_BYTES: usize = 64 * 1_024;
const MAX_CREDENTIAL_BYTES: usize = 128 * 1_024;

/// Validated WebAuthn relying-party and ceremony policy.
pub struct PasskeyServiceConfig {
    webauthn: Webauthn,
    flow_ttl_seconds: u64,
    session_ttl_seconds: u64,
}

impl PasskeyServiceConfig {
    /// Constructs production-validated WebAuthn policy.
    ///
    /// Development permits `http://localhost`; production requires HTTPS. The
    /// origin host must equal the RP ID or be one of its subdomains.
    ///
    /// # Errors
    ///
    /// Rejects malformed RP IDs, origins, names, or unsafe lifetimes.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        rp_id: &str,
        rp_name: &str,
        origin: &str,
        production: bool,
        attachment: Attachment,
        require_user_verification: bool,
        require_user_handle: bool,
        flow_ttl_seconds: u64,
        session_ttl_seconds: u64,
    ) -> Result<Self, PasskeyConfigurationError> {
        if !valid_rp_id(rp_id)
            || rp_name.trim().is_empty()
            || rp_name.len() > 128
            || rp_name.chars().any(char::is_control)
            || !valid_origin_for_rp(origin, rp_id, production)
            || !(60..=15 * 60).contains(&flow_ttl_seconds)
            || !(5 * 60..=24 * 60 * 60).contains(&session_ttl_seconds)
        {
            return Err(PasskeyConfigurationError::Invalid);
        }
        let webauthn = Webauthn::new(rp_id, rp_name, origin)
            .authenticator_attachment(attachment)
            .require_user_verification(require_user_verification)
            .require_user_handle(require_user_handle)
            .strict_base64(true);
        Ok(Self {
            webauthn,
            flow_ttl_seconds,
            session_ttl_seconds,
        })
    }
}

/// Browser challenge and public-key options for one ceremony.
pub struct PasskeyStart {
    challenge_id: String,
    public_key_options_json: String,
    redirect_path: String,
}

impl PasskeyStart {
    /// Takes the challenge identifier, browser options JSON, and redirect path.
    #[must_use]
    pub fn into_parts(mut self) -> (String, String, String) {
        (
            std::mem::take(&mut self.challenge_id),
            std::mem::take(&mut self.public_key_options_json),
            std::mem::take(&mut self.redirect_path),
        )
    }
}

impl fmt::Debug for PasskeyStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PasskeyStart")
            .field("challenge_id", &"[REDACTED]")
            .field("public_key_options_json", &"[REDACTED]")
            .field("redirect_path", &self.redirect_path)
            .finish()
    }
}

impl Drop for PasskeyStart {
    fn drop(&mut self) {
        self.challenge_id.zeroize();
        self.public_key_options_json.zeroize();
    }
}

/// Session established or elevated by a successful passkey ceremony.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PasskeyCompletion {
    /// Session identifier.
    pub session_id: SessionId,
    /// Global user UUID.
    pub user_id: String,
    /// Authoritative primary email.
    pub primary_email: String,
    /// Session expiry in milliseconds since Unix epoch.
    pub expires_at_ms: u64,
    /// Validated local redirect path.
    pub redirect_path: String,
}

#[derive(Serialize, Deserialize)]
#[serde(tag = "flow", rename_all = "snake_case")]
enum StoredPasskeyFlow {
    Registration {
        state: RegistrationState,
        user_id: String,
        primary_email: String,
        redirect_path: String,
    },
    Authentication {
        state: AuthenticationState,
        user_id: String,
        primary_email: String,
        redirect_path: String,
    },
}

struct PendingPasskeyFlow {
    flow: PendingFlow,
    payload: StoredPasskeyFlow,
}

/// PostgreSQL passkey workflow service.
pub struct PasskeyService<T, C, R> {
    flows: EncryptedFlowStore<T, C, R>,
    config: PasskeyServiceConfig,
}

impl<T, C, R> PasskeyService<T, C, R> {
    /// Assembles the passkey service from validated dependencies.
    #[must_use]
    pub const fn new(
        store: PostgresAuthStore<T>,
        clock: C,
        randomness: R,
        sealing_key: FlowSealingKey,
        config: PasskeyServiceConfig,
    ) -> Self {
        Self {
            flows: EncryptedFlowStore::new(store, clock, randomness, sealing_key),
            config,
        }
    }
}

impl<T, C, R> PasskeyService<T, C, R>
where
    T: PostgresTransport,
    C: Clock,
    R: RandomSource,
{
    /// Starts registration for the authoritative user bound to a live session.
    ///
    /// # Errors
    ///
    /// Returns invalid session, redirect, state, row, crypto, or transport failures.
    pub async fn start_registration(
        &self,
        session_id: &SessionId,
        request_id: &RequestId,
        redirect_path: &str,
    ) -> Result<PasskeyStart, PasskeyServiceError<T::Error>> {
        if !safe_redirect_path(redirect_path) {
            return Err(PasskeyServiceError::InvalidInput);
        }
        let session = self
            .flows
            .store()
            .load_verified_session(
                session_id,
                request_id.clone(),
                self.flows.now_unix_seconds(),
            )
            .await
            .map_err(|_| PasskeyServiceError::InvalidSession)?;
        let user_id = session.context().auth().principal().user_id().as_str();
        let credentials = self.load_credentials_for_user(user_id).await?;
        let existing_ids = credentials
            .iter()
            .map(|credential| credential.id.clone())
            .collect::<Vec<_>>();
        let (options, state) = self.config.webauthn.start_registration(
            user_id.as_bytes(),
            session.primary_email(),
            session.primary_email(),
            &existing_ids,
        );
        let options =
            serde_json::to_string(&options).map_err(|_| PasskeyServiceError::Serialization)?;
        let payload = serde_json::to_vec(&StoredPasskeyFlow::Registration {
            state,
            user_id: user_id.to_owned(),
            primary_email: session.primary_email().to_owned(),
            redirect_path: redirect_path.to_owned(),
        })
        .map_err(|_| PasskeyServiceError::Serialization)?;
        let challenge_id = self
            .flows
            .create(
                FlowKind::WebauthnRegistration,
                Some(user_id),
                &payload,
                self.config.flow_ttl_seconds,
            )
            .await?;
        Ok(PasskeyStart {
            challenge_id,
            public_key_options_json: options,
            redirect_path: redirect_path.to_owned(),
        })
    }

    /// Starts a username-first passkey login without revealing account existence.
    ///
    /// # Errors
    ///
    /// Returns invalid credentials, input, state, row, crypto, or transport failures.
    pub async fn start_authentication(
        &self,
        email: &str,
        redirect_path: &str,
    ) -> Result<PasskeyStart, PasskeyServiceError<T::Error>> {
        if !safe_redirect_path(redirect_path) {
            return Err(PasskeyServiceError::InvalidInput);
        }
        let normalized_email = normalize_email(email)?;
        let rows = self
            .query(LOAD_PASSKEYS_FOR_EMAIL_SQL, vec![text(&normalized_email)])
            .await?;
        let (user_id, primary_email, credentials) = credentials_from_rows(&rows)?;
        if credentials.is_empty() {
            return Err(PasskeyServiceError::InvalidCredentials);
        }
        let (options, state) = self
            .config
            .webauthn
            .start_authentication_with_creds_for_user(user_id.as_bytes(), &credentials);
        let options =
            serde_json::to_string(&options).map_err(|_| PasskeyServiceError::Serialization)?;
        let payload = serde_json::to_vec(&StoredPasskeyFlow::Authentication {
            state,
            user_id: user_id.clone(),
            primary_email,
            redirect_path: redirect_path.to_owned(),
        })
        .map_err(|_| PasskeyServiceError::Serialization)?;
        let challenge_id = self
            .flows
            .create(
                FlowKind::WebauthnAuthentication,
                Some(&user_id),
                &payload,
                self.config.flow_ttl_seconds,
            )
            .await?;
        Ok(PasskeyStart {
            challenge_id,
            public_key_options_json: options,
            redirect_path: redirect_path.to_owned(),
        })
    }

    /// Verifies registration before atomically consuming the challenge and
    /// storing the credential for the session user.
    ///
    /// # Errors
    ///
    /// Returns ceremony, replay, session, conflict, row, or transport failures.
    pub async fn finish_registration(
        &self,
        session_id: &SessionId,
        challenge_id: &str,
        credential_json: &str,
        request_id: &RequestId,
        display_name: &str,
    ) -> Result<PasskeyCompletion, PasskeyServiceError<T::Error>> {
        validate_response(credential_json)?;
        if display_name.trim().is_empty()
            || display_name.len() > 128
            || display_name.chars().any(char::is_control)
        {
            return Err(PasskeyServiceError::InvalidInput);
        }
        let session = self
            .flows
            .store()
            .load_verified_session(
                session_id,
                request_id.clone(),
                self.flows.now_unix_seconds(),
            )
            .await
            .map_err(|_| PasskeyServiceError::InvalidSession)?;
        let pending = self
            .load_flow(FlowKind::WebauthnRegistration, challenge_id)
            .await?;
        let StoredPasskeyFlow::Registration {
            state,
            user_id,
            primary_email,
            redirect_path,
        } = pending.payload
        else {
            return Err(PasskeyServiceError::InvalidFlow);
        };
        if pending.flow.user_id.as_deref() != Some(user_id.as_str())
            || session.context().auth().principal().user_id().as_str() != user_id
            || session.primary_email() != primary_email
        {
            return Err(PasskeyServiceError::InvalidSession);
        }
        let response = serde_json::from_str::<RegistrationResponse>(credential_json)
            .map_err(|_| PasskeyServiceError::InvalidResponse)?;
        let credential = self
            .config
            .webauthn
            .finish_registration(&state, &response)
            .map_err(|_| PasskeyServiceError::InvalidResponse)?;
        let encoded =
            serde_json::to_vec(&credential).map_err(|_| PasskeyServiceError::Serialization)?;
        if encoded.len() > MAX_CREDENTIAL_BYTES {
            return Err(PasskeyServiceError::InvalidResponse);
        }
        let now_ms = self.flows.now_unix_seconds().saturating_mul(1_000);
        let audit_id = self
            .flows
            .uuid(now_ms)
            .map_err(|_| PasskeyServiceError::RandomnessUnavailable)?;
        let rows = self
            .query(
                COMPLETE_PASSKEY_REGISTRATION_SQL,
                vec![
                    PgValue::Bytes(pending.flow.verifier_hash.clone()),
                    text(pending.flow.flow_id),
                    text(session_id.as_str()),
                    PgValue::Bytes(credential.id.as_bytes().to_vec()),
                    PgValue::Bytes(encoded),
                    PgValue::I64(i64::from(credential.counter)),
                    PgValue::Json(Value::Array(
                        credential
                            .transports
                            .iter()
                            .cloned()
                            .map(Value::String)
                            .collect(),
                    )),
                    i64_value(now_ms),
                    text(display_name.trim()),
                    text(audit_id),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        completion_from_rows(&rows, "registered", redirect_path)
    }

    /// Verifies an assertion before atomically consuming the challenge,
    /// advancing the credential counter, creating an AAL2 session, and auditing.
    ///
    /// # Errors
    ///
    /// Returns ceremony, replay, counter, row, randomness, or transport failures.
    pub async fn finish_authentication(
        &self,
        challenge_id: &str,
        credential_json: &str,
        request_id: &RequestId,
    ) -> Result<PasskeyCompletion, PasskeyServiceError<T::Error>> {
        validate_response(credential_json)?;
        let pending = self
            .load_flow(FlowKind::WebauthnAuthentication, challenge_id)
            .await?;
        let StoredPasskeyFlow::Authentication {
            state,
            user_id,
            primary_email,
            redirect_path,
        } = pending.payload
        else {
            return Err(PasskeyServiceError::InvalidFlow);
        };
        if pending.flow.user_id.as_deref() != Some(user_id.as_str()) {
            return Err(PasskeyServiceError::InvalidFlow);
        }
        let response = serde_json::from_str::<AuthenticationResponse>(credential_json)
            .map_err(|_| PasskeyServiceError::InvalidResponse)?;
        let credential_id = CredentialId::from_b64url(&response.id)
            .map_err(|_| PasskeyServiceError::InvalidResponse)?;
        let (mut credential, stored_counter) =
            self.load_credential(&user_id, &credential_id).await?;
        let outcome = self
            .config
            .webauthn
            .finish_authentication(&state, &response, &credential)
            .map_err(|_| PasskeyServiceError::InvalidResponse)?;
        credential.counter = outcome.new_counter;
        let encoded =
            serde_json::to_vec(&credential).map_err(|_| PasskeyServiceError::Serialization)?;
        if encoded.len() > MAX_CREDENTIAL_BYTES {
            return Err(PasskeyServiceError::InvalidResponse);
        }
        let now_ms = self.flows.now_unix_seconds().saturating_mul(1_000);
        let session_id = self
            .flows
            .uuid(now_ms)
            .map_err(|_| PasskeyServiceError::RandomnessUnavailable)?;
        let audit_id = self
            .flows
            .uuid(now_ms)
            .map_err(|_| PasskeyServiceError::RandomnessUnavailable)?;
        let rows = self
            .query(
                COMPLETE_PASSKEY_AUTHENTICATION_SQL,
                vec![
                    PgValue::Bytes(pending.flow.verifier_hash.clone()),
                    text(pending.flow.flow_id),
                    text(&user_id),
                    PgValue::Bytes(credential.id.as_bytes().to_vec()),
                    PgValue::Bytes(encoded),
                    PgValue::I64(i64::from(stored_counter)),
                    PgValue::I64(i64::from(credential.counter)),
                    PgValue::Json(Value::Array(
                        credential
                            .transports
                            .iter()
                            .cloned()
                            .map(Value::String)
                            .collect(),
                    )),
                    text(session_id),
                    i64_value(
                        now_ms
                            .saturating_add(self.config.session_ttl_seconds.saturating_mul(1_000)),
                    ),
                    text(audit_id),
                    i64_value(now_ms),
                    text(request_id.as_str()),
                ],
            )
            .await?;
        let completion = completion_from_rows(&rows, "authenticated", redirect_path)?;
        if completion.primary_email != primary_email {
            return Err(PasskeyServiceError::InvalidCredentials);
        }
        Ok(completion)
    }

    async fn load_flow(
        &self,
        kind: FlowKind,
        challenge_id: &str,
    ) -> Result<PendingPasskeyFlow, PasskeyServiceError<T::Error>> {
        let mut flow = self.flows.load(kind, challenge_id).await?;
        let payload = serde_json::from_slice::<StoredPasskeyFlow>(&flow.payload)
            .map_err(|_| PasskeyServiceError::Serialization)?;
        flow.payload.zeroize();
        Ok(PendingPasskeyFlow { flow, payload })
    }

    async fn load_credentials_for_user(
        &self,
        user_id: &str,
    ) -> Result<Vec<PasskeyCredential>, PasskeyServiceError<T::Error>> {
        let rows = self
            .query(LOAD_PASSKEYS_FOR_USER_SQL, vec![text(user_id)])
            .await?;
        Ok(credentials_from_rows(&rows)?.2)
    }

    async fn load_credential(
        &self,
        user_id: &str,
        credential_id: &CredentialId,
    ) -> Result<(PasskeyCredential, u32), PasskeyServiceError<T::Error>> {
        let rows = self
            .query(
                LOAD_PASSKEY_CREDENTIAL_SQL,
                vec![
                    text(user_id),
                    PgValue::Bytes(credential_id.as_bytes().to_vec()),
                ],
            )
            .await?;
        let row = rows
            .first()
            .ok_or(PasskeyServiceError::InvalidCredentials)?;
        let credential = decode_credential(row)?;
        let counter = u32::try_from(row.required_i64("sign_count")?)
            .map_err(|_| PasskeyServiceError::InvalidRow)?;
        if credential.counter != counter {
            return Err(PasskeyServiceError::InvalidRow);
        }
        Ok((credential, counter))
    }

    async fn query(
        &self,
        sql: &'static str,
        values: Vec<PgValue>,
    ) -> Result<Vec<PgRow>, PasskeyServiceError<T::Error>> {
        self.flows
            .transport()
            .query(sql, values)
            .await
            .map_err(PasskeyServiceError::Transport)
    }
}

fn credentials_from_rows<E>(
    rows: &[PgRow],
) -> Result<(String, String, Vec<PasskeyCredential>), PasskeyServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let first = rows
        .first()
        .ok_or(PasskeyServiceError::InvalidCredentials)?;
    let user_id = first.required_text("user_id")?.to_owned();
    let primary_email = first.required_text("primary_email")?.to_owned();
    let credentials = rows
        .iter()
        .filter(|row| row.bytes("public_key_cose").ok().flatten().is_some())
        .map(decode_credential)
        .collect::<Result<Vec<_>, _>>()?;
    Ok((user_id, primary_email, credentials))
}

fn decode_credential<E>(row: &PgRow) -> Result<PasskeyCredential, PasskeyServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let credential =
        serde_json::from_slice::<PasskeyCredential>(row.required_bytes("public_key_cose")?)
            .map_err(|_| PasskeyServiceError::InvalidRow)?;
    if row
        .bytes("credential_id")?
        .is_some_and(|id| id != credential.id.as_bytes())
    {
        return Err(PasskeyServiceError::InvalidRow);
    }
    Ok(credential)
}

fn completion_from_rows<E>(
    rows: &[PgRow],
    expected: &str,
    redirect_path: String,
) -> Result<PasskeyCompletion, PasskeyServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let row = rows.first().ok_or(PasskeyServiceError::InvalidFlow)?;
    match row.required_text("outcome")? {
        outcome if outcome == expected => Ok(PasskeyCompletion {
            session_id: SessionId::new(row.required_text("session_id")?.to_owned())
                .map_err(|_| PasskeyServiceError::InvalidRow)?,
            user_id: row.required_text("user_id")?.to_owned(),
            primary_email: row.required_text("primary_email")?.to_owned(),
            expires_at_ms: u64::try_from(row.required_i64("expires_at_ms")?)
                .map_err(|_| PasskeyServiceError::InvalidRow)?,
            redirect_path,
        }),
        "credential_conflict" => Err(PasskeyServiceError::CredentialConflict),
        "counter_conflict" => Err(PasskeyServiceError::CounterConflict),
        _ => Err(PasskeyServiceError::InvalidRow),
    }
}

fn validate_response<E>(value: &str) -> Result<(), PasskeyServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    if value.is_empty() || value.len() > MAX_CREDENTIAL_RESPONSE_BYTES {
        Err(PasskeyServiceError::InvalidResponse)
    } else {
        Ok(())
    }
}

fn normalize_email<E>(value: &str) -> Result<String, PasskeyServiceError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let normalized = value.trim().to_ascii_lowercase();
    if normalized.len() > 320
        || normalized.starts_with('@')
        || normalized.ends_with('@')
        || normalized.matches('@').count() != 1
        || normalized.chars().any(char::is_control)
    {
        Err(PasskeyServiceError::InvalidInput)
    } else {
        Ok(normalized)
    }
}

fn safe_redirect_path(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= 2_048
        && !value.chars().any(char::is_control)
}

fn valid_rp_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && !value.contains("://")
        && !value.contains(['/', ':', '@'])
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
}

fn valid_origin_for_rp(origin: &str, rp_id: &str, production: bool) -> bool {
    let authority = if let Some(value) = origin.strip_prefix("https://") {
        value
    } else if !production {
        let Some(value) = origin.strip_prefix("http://") else {
            return false;
        };
        value
    } else {
        return false;
    };
    if authority.is_empty()
        || authority.contains(['/', '?', '#', '@'])
        || authority.chars().any(char::is_control)
    {
        return false;
    }
    let host = authority.split(':').next().unwrap_or_default();
    (host == rp_id || host.ends_with(&format!(".{rp_id}")))
        && (!production || !host.eq_ignore_ascii_case("localhost"))
}

/// Invalid WebAuthn relying-party or lifetime policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PasskeyConfigurationError {
    /// Configuration violated production WebAuthn policy.
    #[error("passkey configuration is invalid")]
    Invalid,
}

/// Passkey ceremony or persistence failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum PasskeyServiceError<E: StdError + Send + Sync + 'static> {
    /// Request, redirect, email, or display name was invalid.
    #[error("passkey input is invalid")]
    InvalidInput,
    /// Browser response was malformed or failed WebAuthn verification.
    #[error("passkey response is invalid")]
    InvalidResponse,
    /// Challenge was absent, expired, consumed, tampered, or had the wrong kind.
    #[error("passkey challenge is invalid or expired")]
    InvalidFlow,
    /// Session was missing, expired, revoked, stale, or bound to another user.
    #[error("passkey session is invalid")]
    InvalidSession,
    /// Account or credential did not authenticate.
    #[error("passkey credentials are invalid")]
    InvalidCredentials,
    /// Credential already belongs to an account.
    #[error("passkey credential is already registered")]
    CredentialConflict,
    /// Stored authenticator counter changed concurrently.
    #[error("passkey authenticator counter changed concurrently")]
    CounterConflict,
    /// Host randomness failed.
    #[error("cryptographic randomness is unavailable")]
    RandomnessUnavailable,
    /// Passkey state or credential serialization failed.
    #[error("passkey serialization failed")]
    Serialization,
    /// Shared encrypted-flow handling failed.
    #[error(transparent)]
    Flow(#[from] FlowStoreError<E>),
    /// PostgreSQL transport failed.
    #[error("PostgreSQL passkey transport failed: {0}")]
    Transport(#[source] E),
    /// PostgreSQL row decoding failed.
    #[error(transparent)]
    Row(#[from] RowDecodeError),
    /// PostgreSQL returned malformed passkey data.
    #[error("PostgreSQL returned malformed passkey data")]
    InvalidRow,
}
