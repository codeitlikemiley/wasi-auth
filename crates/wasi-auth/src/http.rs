//! Native trusted-ingress authentication and HTTP security policy.
//!
//! The HMAC envelope in [`AUTH_CONTEXT_HEADER`] is the only context this crate
//! will turn into a [`VerifiedAuthContext`]. The portable middleware context
//! uses the same header name and a different, unsigned encoding. Those bytes
//! are not a credential here and never install authority.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::future::Future;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use hmac::{Hmac, Mac};
use http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD,
    AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, COOKIE, ORIGIN,
    PROXY_AUTHORIZATION, REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, VARY, X_CONTENT_TYPE_OPTIONS,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use thiserror::Error;
use zeroize::Zeroize;

use crate::authentication::Clock;
use crate::context::{
    AuthenticationAssurance, AuthorizationSnapshot, ContextError, DecisionId, OrganizationId,
    PolicyRevision, Principal, RequestId, RoleId, SessionId, UserId, ValidatedContextParts,
    VerifiedAuthContext, VerifiedRequestContext,
};

/// Default bounded body size for auth, REST, and unary gRPC requests.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 256 * 1024;
/// Maximum forwarded body for one streaming request.
///
/// This is 100 messages at [`DEFAULT_MAX_REQUEST_BODY_BYTES`], matching the
/// gRPC stream message budget. It is not a second authentication policy.
pub const DEFAULT_MAX_STREAM_BODY_BYTES: usize = 100 * DEFAULT_MAX_REQUEST_BODY_BYTES;
/// Canonical request correlation header.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
/// Internal identity metadata header removed from every public request.
pub const AUTH_CONTEXT_HEADER: HeaderName = HeaderName::from_static("x-wasi-auth-context");
/// Maximum signed trusted-context header size accepted by the guest boundary.
pub const MAX_TRUSTED_CONTEXT_HEADER_BYTES: usize = 32 * 1024;
const TRUSTED_CONTEXT_VERSION: u8 = 1;
const DEFAULT_TRUSTED_CONTEXT_MAX_AGE_SECONDS: u64 = 5;
const TRUSTED_CONTEXT_DOMAIN: &[u8] = b"wasi-auth:trusted-context:v1\0";
const RESERVED_AUTH_PREFIX: &str = "x-wasi-auth-";
const LEGACY_SESSION_HEADER: HeaderName = HeaderName::from_static("x-auth-session");
const LEGACY_ADMIN_HEADER: HeaderName = HeaderName::from_static("x-auth-admin-token");
const HOST_SESSION_COOKIE: &str = "__Host-session";
const DEVELOPMENT_SESSION_COOKIE: &str = "wasi_auth_dev_session";
const CANONICAL_REFERRER_POLICY: &str = "same-origin";
const CANONICAL_CONTENT_SECURITY_POLICY: &str =
    "default-src 'self'; frame-ancestors 'none'; base-uri 'self'";
const CANONICAL_CONTENT_TYPE_OPTIONS: &str = "nosniff";
const CANONICAL_HSTS: &str = "max-age=31536000; includeSubDomains";
/// Browser CSRF header paired with the host-only CSRF cookie.
pub const CSRF_HEADER: HeaderName = HeaderName::from_static("x-csrf-token");

/// Signed-context configuration or validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TrustedContextError {
    /// The key, audience, or maximum age is unsafe.
    #[error("trusted-context configuration is invalid")]
    InvalidConfiguration,
    /// The envelope is malformed, oversized, or has an invalid signature.
    #[error("trusted-context envelope is invalid")]
    InvalidEnvelope,
    /// The envelope is stale, from the future, or carries an expired session.
    #[error("trusted-context envelope has expired")]
    Expired,
    /// The envelope was issued for another request boundary.
    #[error("trusted-context request binding does not match")]
    BindingMismatch,
    /// The signed values violate the bounded request-context contract.
    #[error("trusted-context payload is invalid")]
    InvalidContext,
}

/// HMAC-SHA-256 codec for the native-ingress to guest trust boundary.
///
/// Envelopes are short-lived and bound to audience, method, path, and request
/// ID. The key is deployment secret material shared only by the native ingress
/// and the loopback-only Spin application.
pub struct TrustedContextCodec {
    audience: String,
    key: [u8; 32],
    max_age_seconds: u64,
}

impl TrustedContextCodec {
    /// Constructs a codec with a five-second replay window.
    ///
    /// # Errors
    ///
    /// Rejects empty/unbounded audiences and an all-zero key.
    pub fn new(audience: impl Into<String>, key: [u8; 32]) -> Result<Self, TrustedContextError> {
        let audience = audience.into();
        if audience.is_empty()
            || audience.len() > 256
            || audience.chars().any(char::is_control)
            || key.iter().all(|byte| *byte == 0)
        {
            return Err(TrustedContextError::InvalidConfiguration);
        }
        Ok(Self {
            audience,
            key,
            max_age_seconds: DEFAULT_TRUSTED_CONTEXT_MAX_AGE_SECONDS,
        })
    }

    /// Overrides the bounded replay window.
    ///
    /// # Errors
    ///
    /// Rejects zero or windows longer than thirty seconds.
    pub fn with_max_age_seconds(
        mut self,
        max_age_seconds: u64,
    ) -> Result<Self, TrustedContextError> {
        if !(1..=30).contains(&max_age_seconds) {
            return Err(TrustedContextError::InvalidConfiguration);
        }
        self.max_age_seconds = max_age_seconds;
        Ok(self)
    }

    /// Seals a verified request context for one internal request boundary.
    ///
    /// # Errors
    ///
    /// Rejects invalid path metadata, inconsistent policy revisions, expired
    /// contexts, or envelopes that exceed the bounded header size.
    pub fn seal(
        &self,
        context: &VerifiedRequestContext,
        method: &Method,
        path: &str,
        now_unix_seconds: u64,
    ) -> Result<String, TrustedContextError> {
        validate_trusted_path(path)?;
        if context.auth().expires_at_unix_seconds() <= now_unix_seconds {
            return Err(TrustedContextError::Expired);
        }
        let auth_policy_revision = context.auth().policy_revision().map(ToString::to_string);
        let authorization_policy_revision = context
            .authorization()
            .policy_revision()
            .map(ToString::to_string);
        if auth_policy_revision != authorization_policy_revision {
            return Err(TrustedContextError::InvalidContext);
        }
        let payload = TrustedContextPayload {
            version: TRUSTED_CONTEXT_VERSION,
            audience: self.audience.clone(),
            method: method.as_str().to_owned(),
            path: path.to_owned(),
            sealed_at_unix_seconds: now_unix_seconds,
            user_id: context.auth().principal().user_id().to_string(),
            issuer: context.auth().principal().issuer().to_owned(),
            system_administrator: context.auth().principal().is_system_administrator(),
            organization_id: context.auth().organization_id().map(ToString::to_string),
            session_id: context.auth().session_id().to_string(),
            request_id: context.auth().request_id().to_string(),
            assurance: context.auth().assurance(),
            issued_at_unix_seconds: context.auth().issued_at_unix_seconds(),
            expires_at_unix_seconds: context.auth().expires_at_unix_seconds(),
            decision_id: context.auth().decision_id().map(ToString::to_string),
            policy_revision: auth_policy_revision,
            permissions: context
                .authorization()
                .permissions()
                .map(str::to_owned)
                .collect(),
            role_ids: context
                .authorization()
                .role_ids()
                .map(ToString::to_string)
                .collect(),
            consistency_token: context
                .authorization()
                .consistency_token()
                .map(str::to_owned),
        };
        let payload =
            serde_json::to_vec(&payload).map_err(|_| TrustedContextError::InvalidEnvelope)?;
        let payload = URL_SAFE_NO_PAD.encode(payload);
        let signature = self.signature(payload.as_bytes())?;
        let envelope = format!("{payload}.{}", URL_SAFE_NO_PAD.encode(signature));
        if envelope.len() > MAX_TRUSTED_CONTEXT_HEADER_BYTES {
            return Err(TrustedContextError::InvalidEnvelope);
        }
        Ok(envelope)
    }

    /// Opens and reconstructs a verified context only when signature,
    /// freshness, audience, method, path, and request ID all match.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed, stale, replayed-across-boundary, or invalid
    /// context data.
    pub fn open(
        &self,
        envelope: &str,
        method: &Method,
        path: &str,
        request_id: &str,
        now_unix_seconds: u64,
    ) -> Result<VerifiedRequestContext, TrustedContextError> {
        validate_trusted_path(path)?;
        if envelope.len() > MAX_TRUSTED_CONTEXT_HEADER_BYTES {
            return Err(TrustedContextError::InvalidEnvelope);
        }
        let (payload, signature) = envelope
            .split_once('.')
            .filter(|(_, signature)| !signature.contains('.'))
            .ok_or(TrustedContextError::InvalidEnvelope)?;
        let mut signature = URL_SAFE_NO_PAD
            .decode(signature)
            .map_err(|_| TrustedContextError::InvalidEnvelope)?;
        let mut verifier = self.mac()?;
        verifier.update(payload.as_bytes());
        let verification = verifier.verify_slice(&signature);
        signature.zeroize();
        verification.map_err(|_| TrustedContextError::InvalidEnvelope)?;
        let payload = URL_SAFE_NO_PAD
            .decode(payload)
            .map_err(|_| TrustedContextError::InvalidEnvelope)?;
        let payload: TrustedContextPayload =
            serde_json::from_slice(&payload).map_err(|_| TrustedContextError::InvalidEnvelope)?;
        if payload.version != TRUSTED_CONTEXT_VERSION
            || payload.audience != self.audience
            || payload.method != method.as_str()
            || payload.path != path
            || payload.request_id != request_id
        {
            return Err(TrustedContextError::BindingMismatch);
        }
        if payload.sealed_at_unix_seconds > now_unix_seconds.saturating_add(1)
            || now_unix_seconds.saturating_sub(payload.sealed_at_unix_seconds)
                > self.max_age_seconds
            || payload.expires_at_unix_seconds <= now_unix_seconds
        {
            return Err(TrustedContextError::Expired);
        }
        let policy_revision = payload
            .policy_revision
            .map(PolicyRevision::new)
            .transpose()
            .map_err(|_| TrustedContextError::InvalidContext)?;
        let principal = Principal::new(
            UserId::new(payload.user_id).map_err(|_| TrustedContextError::InvalidContext)?,
            payload.issuer,
            payload.system_administrator,
        )
        .map_err(|_| TrustedContextError::InvalidContext)?;
        let auth = VerifiedAuthContext::from_validated(ValidatedContextParts {
            principal,
            organization_id: payload
                .organization_id
                .map(OrganizationId::new)
                .transpose()
                .map_err(|_| TrustedContextError::InvalidContext)?,
            session_id: SessionId::new(payload.session_id)
                .map_err(|_| TrustedContextError::InvalidContext)?,
            request_id: RequestId::new(payload.request_id)
                .map_err(|_| TrustedContextError::InvalidContext)?,
            assurance: payload.assurance,
            issued_at_unix_seconds: payload.issued_at_unix_seconds,
            expires_at_unix_seconds: payload.expires_at_unix_seconds,
            decision_id: payload
                .decision_id
                .map(DecisionId::new)
                .transpose()
                .map_err(|_| TrustedContextError::InvalidContext)?,
            policy_revision: policy_revision.clone(),
        })
        .map_err(|_| TrustedContextError::InvalidContext)?;
        let authorization = AuthorizationSnapshot::new(
            payload.permissions,
            payload
                .role_ids
                .into_iter()
                .map(RoleId::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| TrustedContextError::InvalidContext)?,
            policy_revision,
            payload.consistency_token,
        )
        .map_err(|_| TrustedContextError::InvalidContext)?;
        Ok(VerifiedRequestContext::from_verified(auth, authorization))
    }

    fn signature(&self, payload: &[u8]) -> Result<Vec<u8>, TrustedContextError> {
        let mut mac = self.mac()?;
        mac.update(payload);
        Ok(mac.finalize().into_bytes().to_vec())
    }

    fn mac(&self) -> Result<Hmac<Sha256>, TrustedContextError> {
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.key)
            .map_err(|_| TrustedContextError::InvalidConfiguration)?;
        mac.update(TRUSTED_CONTEXT_DOMAIN);
        Ok(mac)
    }
}

impl std::fmt::Debug for TrustedContextCodec {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TrustedContextCodec")
            .field("audience", &self.audience)
            .field("key", &"[REDACTED]")
            .field("max_age_seconds", &self.max_age_seconds)
            .finish()
    }
}

impl Drop for TrustedContextCodec {
    fn drop(&mut self) {
        self.key.zeroize();
    }
}

#[derive(Deserialize, Serialize)]
struct TrustedContextPayload {
    version: u8,
    audience: String,
    method: String,
    path: String,
    sealed_at_unix_seconds: u64,
    user_id: String,
    issuer: String,
    system_administrator: bool,
    organization_id: Option<String>,
    session_id: String,
    request_id: String,
    assurance: AuthenticationAssurance,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    decision_id: Option<String>,
    policy_revision: Option<String>,
    permissions: Vec<String>,
    role_ids: Vec<String>,
    consistency_token: Option<String>,
}

fn validate_trusted_path(path: &str) -> Result<(), TrustedContextError> {
    if path.is_empty()
        || path.len() > 2_048
        || !path.starts_with('/')
        || path.chars().any(char::is_control)
    {
        return Err(TrustedContextError::BindingMismatch);
    }
    Ok(())
}

/// CORS configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CorsError {
    /// An origin, method, or header was invalid.
    #[error("CORS configuration is invalid")]
    InvalidConfiguration,
    /// A preflight request was malformed or not allowed.
    #[error("CORS preflight request is not allowed")]
    PreflightRejected,
}

/// Exact-origin CORS policy. Wildcard credentialed origins are not supported.
#[derive(Clone, Debug)]
pub struct CorsConfig {
    allowed_origins: BTreeSet<String>,
    allowed_methods: BTreeSet<String>,
    allowed_headers: BTreeSet<String>,
    allow_credentials: bool,
}

impl CorsConfig {
    /// Creates an exact allowlist policy.
    ///
    /// # Errors
    ///
    /// Returns [`CorsError::InvalidConfiguration`] when any set is empty or
    /// contains malformed values.
    pub fn new(
        allowed_origins: impl IntoIterator<Item = impl Into<String>>,
        allowed_methods: impl IntoIterator<Item = impl Into<String>>,
        allowed_headers: impl IntoIterator<Item = impl Into<String>>,
        allow_credentials: bool,
    ) -> Result<Self, CorsError> {
        let allowed_origins = allowed_origins
            .into_iter()
            .map(Into::into)
            .collect::<BTreeSet<String>>();
        let allowed_methods = allowed_methods
            .into_iter()
            .map(|value| value.into().to_ascii_uppercase())
            .collect::<BTreeSet<String>>();
        let allowed_headers = allowed_headers
            .into_iter()
            .map(|value| value.into().to_ascii_lowercase())
            .collect::<BTreeSet<String>>();
        if allowed_origins.is_empty()
            || allowed_methods.is_empty()
            || allowed_origins.iter().any(|origin| {
                origin == "*"
                    || origin.chars().any(char::is_control)
                    || (!origin.starts_with("https://")
                        && !origin.starts_with("http://localhost")
                        && !origin.starts_with("http://127.0.0.1")
                        && !origin.starts_with("http://[::1]"))
            })
            || allowed_methods
                .iter()
                .any(|method| Method::from_bytes(method.as_bytes()).is_err())
            || allowed_headers.iter().any(|header| {
                header.is_empty() || HeaderName::from_bytes(header.as_bytes()).is_err()
            })
        {
            return Err(CorsError::InvalidConfiguration);
        }
        Ok(Self {
            allowed_origins,
            allowed_methods,
            allowed_headers,
            allow_credentials,
        })
    }

    /// Applies simple-request CORS response headers for an allowed origin.
    ///
    /// Returns `false` without adding headers when the origin is absent, not
    /// allowed, or the response already carries CORS headers from another
    /// policy. An existing allow-origin is left unchanged so two CORS policies
    /// cannot be composed onto one response.
    pub fn apply<B>(&self, request_headers: &HeaderMap, response: &mut Response<B>) -> bool {
        if response.headers().contains_key(ACCESS_CONTROL_ALLOW_ORIGIN)
            || response
                .headers()
                .contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS)
        {
            return false;
        }
        let Some(origin) = request_headers
            .get(ORIGIN)
            .and_then(|value| value.to_str().ok())
        else {
            return false;
        };
        if !self.allowed_origins.contains(origin) {
            return false;
        }
        let Ok(origin) = HeaderValue::from_str(origin) else {
            return false;
        };
        let headers = response.headers_mut();
        headers.insert(ACCESS_CONTROL_ALLOW_ORIGIN, origin);
        headers.insert(VARY, HeaderValue::from_static("Origin"));
        if self.allow_credentials {
            headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        true
    }

    /// Builds a bounded successful preflight response.
    ///
    /// # Errors
    ///
    /// Returns [`CorsError::PreflightRejected`] when origin, method, or headers
    /// are missing or not allowlisted.
    pub fn preflight(&self, request_headers: &HeaderMap) -> Result<Response<()>, CorsError> {
        let origin = request_headers
            .get(ORIGIN)
            .and_then(|value| value.to_str().ok())
            .filter(|origin| self.allowed_origins.contains(*origin))
            .ok_or(CorsError::PreflightRejected)?;
        let method = request_headers
            .get(ACCESS_CONTROL_REQUEST_METHOD)
            .and_then(|value| value.to_str().ok())
            .map(str::to_ascii_uppercase)
            .filter(|method| self.allowed_methods.contains(method))
            .ok_or(CorsError::PreflightRejected)?;
        let requested_headers = request_headers
            .get(ACCESS_CONTROL_REQUEST_HEADERS)
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .split(',')
            .map(str::trim)
            .filter(|header| !header.is_empty())
            .map(str::to_ascii_lowercase)
            .collect::<BTreeSet<_>>();
        if !requested_headers.is_subset(&self.allowed_headers) {
            return Err(CorsError::PreflightRejected);
        }
        let mut response = Response::builder()
            .status(StatusCode::NO_CONTENT)
            .body(())
            .map_err(|_| CorsError::PreflightRejected)?;
        let headers = response.headers_mut();
        headers.insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_str(origin).map_err(|_| CorsError::PreflightRejected)?,
        );
        headers.insert(
            ACCESS_CONTROL_ALLOW_METHODS,
            HeaderValue::from_str(&method).map_err(|_| CorsError::PreflightRejected)?,
        );
        if !requested_headers.is_empty() {
            let headers_value = requested_headers.into_iter().collect::<Vec<_>>().join(", ");
            headers.insert(
                ACCESS_CONTROL_ALLOW_HEADERS,
                HeaderValue::from_str(&headers_value).map_err(|_| CorsError::PreflightRejected)?,
            );
        }
        headers.insert(VARY, HeaderValue::from_static("Origin"));
        if self.allow_credentials {
            headers.insert(
                ACCESS_CONTROL_ALLOW_CREDENTIALS,
                HeaderValue::from_static("true"),
            );
        }
        Ok(response)
    }
}

/// HTTP boundary failure with a stable public status mapping.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum HttpBoundaryError<E>
where
    E: StdError + Send + Sync + 'static,
{
    /// Request body metadata exceeded the route policy.
    #[error("request body exceeds its configured limit")]
    BodyTooLarge,
    /// Content-Length was malformed or duplicated.
    #[error("request body length is invalid")]
    InvalidContentLength,
    /// Required request correlation was missing or malformed.
    #[error("request correlation is invalid")]
    InvalidRequestId,
    /// Multiple or malformed credential headers were supplied.
    #[error("request credentials are invalid")]
    InvalidCredentials,
    /// A protected route did not carry credentials.
    #[error("request credentials are required")]
    MissingCredentials,
    /// Credential validation failed or was unavailable.
    #[error("credential authentication failed")]
    Authenticator(#[source] E),
    /// The authenticated context violated lifetime or identity invariants.
    #[error("authenticated context is invalid")]
    InvalidContext(#[source] ContextError),
    /// The credential did not satisfy route assurance.
    #[error("authentication assurance is insufficient")]
    InsufficientAssurance,
    /// A browser mutation failed origin or CSRF validation.
    #[error("browser request failed CSRF validation")]
    Csrf,
}

impl<E> HttpBoundaryError<E>
where
    E: StdError + Send + Sync + 'static,
{
    /// Returns the safe HTTP status for the boundary failure.
    #[must_use]
    pub const fn status_code(&self) -> StatusCode {
        match self {
            Self::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
            Self::InvalidContentLength
            | Self::InvalidRequestId
            | Self::InvalidCredentials
            | Self::Csrf => StatusCode::BAD_REQUEST,
            Self::MissingCredentials | Self::InsufficientAssurance => StatusCode::UNAUTHORIZED,
            Self::Authenticator(_) | Self::InvalidContext(_) => StatusCode::SERVICE_UNAVAILABLE,
        }
    }
}

/// Credential extracted from the public HTTP request.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum Credential {
    /// Authorization bearer token.
    Bearer(String),
    /// Host-only browser session cookie.
    SessionCookie(String),
}

impl std::fmt::Debug for Credential {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Bearer(_) => formatter.write_str("Bearer([REDACTED])"),
            Self::SessionCookie(_) => formatter.write_str("SessionCookie([REDACTED])"),
        }
    }
}

/// Session result returned by a concrete credential authenticator.
#[derive(Clone, Debug)]
pub struct AuthenticatedSession {
    /// Authenticated principal.
    pub principal: Principal,
    /// Selected organization, if the session has completed tenant selection.
    pub organization_id: Option<OrganizationId>,
    /// Stable session identifier.
    pub session_id: SessionId,
    /// Authentication assurance established for this session.
    pub assurance: AuthenticationAssurance,
    /// Session issue time.
    pub issued_at_unix_seconds: u64,
    /// Session expiry time.
    pub expires_at_unix_seconds: u64,
    /// Optional upstream authorization decision identifier.
    pub decision_id: Option<DecisionId>,
    /// Optional upstream policy revision.
    pub policy_revision: Option<PolicyRevision>,
    /// Current roles, permissions, and consistency loaded from authoritative
    /// storage during authentication.
    pub authorization: AuthorizationSnapshot,
}

/// Concrete credential validator used by native trusted ingress.
pub trait CredentialAuthenticator: Sync {
    /// Authentication provider failure.
    type Error: StdError + Send + Sync + 'static;

    /// Validates one credential and returns a session envelope.
    fn authenticate<'a>(
        &'a self,
        credential: &'a Credential,
    ) -> impl Future<Output = Result<AuthenticatedSession, Self::Error>> + Send + 'a;
}

/// Authentication requirements for one route class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum RoutePolicy {
    /// No credential is accepted or required.
    Public,
    /// Browser form route requiring origin and CSRF validation but no session.
    PublicForm,
    /// A credential is validated when present.
    Optional,
    /// A primary credential is required.
    Authenticated,
    /// Cookie-backed mutation requiring primary authentication and CSRF.
    SessionMutation,
    /// MFA or phishing-resistant assurance is required.
    StepUp,
}

impl RoutePolicy {
    const fn required_assurance(self) -> Option<AuthenticationAssurance> {
        match self {
            Self::Public | Self::PublicForm | Self::Optional => None,
            Self::Authenticated | Self::SessionMutation => Some(AuthenticationAssurance::Aal1),
            Self::StepUp => Some(AuthenticationAssurance::Aal2),
        }
    }
}

/// Validated trusted-ingress HTTP policy.
#[derive(Clone, Debug)]
pub struct TrustedIngressConfig {
    max_request_body_bytes: usize,
    allowed_browser_origin: String,
    allow_development_session_cookie: bool,
}

impl TrustedIngressConfig {
    /// Constructs a policy with a 256 KiB request limit.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError::InvalidIdentifier`] for an empty or control-
    /// character-containing browser origin.
    pub fn new(allowed_browser_origin: impl Into<String>) -> Result<Self, ContextError> {
        let allowed_browser_origin = allowed_browser_origin.into();
        if allowed_browser_origin.is_empty() || allowed_browser_origin.chars().any(char::is_control)
        {
            return Err(ContextError::InvalidIdentifier);
        }
        Ok(Self {
            max_request_body_bytes: DEFAULT_MAX_REQUEST_BODY_BYTES,
            allowed_browser_origin,
            allow_development_session_cookie: false,
        })
    }

    /// Overrides the maximum buffered request size.
    #[must_use]
    pub const fn with_max_request_body_bytes(mut self, bytes: usize) -> Self {
        self.max_request_body_bytes = bytes;
        self
    }

    /// Returns the maximum request size.
    #[must_use]
    pub const fn max_request_body_bytes(&self) -> usize {
        self.max_request_body_bytes
    }

    /// Allows the non-Secure development cookie on loopback origins only.
    #[must_use]
    pub fn with_development_session_cookie(mut self) -> Self {
        self.allow_development_session_cookie =
            self.allowed_browser_origin.starts_with("http://localhost")
                || self.allowed_browser_origin.starts_with("http://127.0.0.1")
                || self.allowed_browser_origin.starts_with("http://[::1]");
        self
    }
}

/// Native request authenticator that installs a canonical verified context.
#[derive(Clone, Debug)]
pub struct TrustedIngress<A, C> {
    config: TrustedIngressConfig,
    authenticator: A,
    clock: C,
}

impl<A, C> TrustedIngress<A, C>
where
    A: CredentialAuthenticator,
    C: Clock,
{
    /// Constructs trusted ingress with concrete static-dispatch dependencies.
    #[must_use]
    pub const fn new(config: TrustedIngressConfig, authenticator: A, clock: C) -> Self {
        Self {
            config,
            authenticator,
            clock,
        }
    }

    /// Validates HTTP metadata and authenticates a route request.
    ///
    /// The caller must first invoke [`strip_untrusted_auth_metadata`] before
    /// forwarding a request across any internal trust boundary.
    ///
    /// # Errors
    ///
    /// Returns [`HttpBoundaryError`] for malformed requests, authentication
    /// failures, expired context, or insufficient assurance.
    pub async fn authenticate<B>(
        &self,
        request: &Request<B>,
        policy: RoutePolicy,
    ) -> Result<Option<VerifiedAuthContext>, HttpBoundaryError<A::Error>> {
        self.authenticate_request(request, policy)
            .await
            .map(|context| context.map(|context| context.into_parts().0))
    }

    /// Validates HTTP metadata and returns identity plus current authorization
    /// facts as one sealed request context.
    ///
    /// # Errors
    ///
    /// Returns [`HttpBoundaryError`] for malformed requests, authentication
    /// failures, expired sessions, or insufficient assurance.
    pub async fn authenticate_request<B>(
        &self,
        request: &Request<B>,
        policy: RoutePolicy,
    ) -> Result<Option<VerifiedRequestContext>, HttpBoundaryError<A::Error>> {
        validate_content_length(request.headers(), self.config.max_request_body_bytes)?;
        let request_id = request_id(request.headers())?;
        let credential = credential(
            request.headers(),
            self.config.allow_development_session_cookie,
        )?;
        let browser_mutation = requires_csrf(request.method())
            && matches!(
                policy,
                RoutePolicy::PublicForm | RoutePolicy::SessionMutation
            )
            && !matches!(&credential, Some(Credential::Bearer(_)));
        if browser_mutation {
            validate_csrf(request.headers(), &self.config.allowed_browser_origin)?;
        }
        let Some(credential) = credential else {
            return match policy {
                RoutePolicy::Public | RoutePolicy::PublicForm | RoutePolicy::Optional => Ok(None),
                RoutePolicy::Authenticated | RoutePolicy::SessionMutation | RoutePolicy::StepUp => {
                    Err(HttpBoundaryError::MissingCredentials)
                }
            };
        };
        if matches!(policy, RoutePolicy::Public | RoutePolicy::PublicForm) {
            return Err(HttpBoundaryError::InvalidCredentials);
        }
        let session = self
            .authenticator
            .authenticate(&credential)
            .await
            .map_err(HttpBoundaryError::Authenticator)?;
        if self.clock.now_unix_seconds() >= session.expires_at_unix_seconds {
            return Err(HttpBoundaryError::InvalidContext(
                ContextError::InvalidLifetime,
            ));
        }
        if policy
            .required_assurance()
            .is_some_and(|required| !session.assurance.satisfies(required))
        {
            return Err(HttpBoundaryError::InsufficientAssurance);
        }
        let auth = VerifiedAuthContext::from_validated(ValidatedContextParts {
            principal: session.principal,
            organization_id: session.organization_id,
            session_id: session.session_id,
            request_id,
            assurance: session.assurance,
            issued_at_unix_seconds: session.issued_at_unix_seconds,
            expires_at_unix_seconds: session.expires_at_unix_seconds,
            decision_id: session.decision_id,
            policy_revision: session.policy_revision,
        })
        .map_err(HttpBoundaryError::InvalidContext)?;
        Ok(Some(VerifiedRequestContext::from_verified(
            auth,
            session.authorization,
        )))
    }
}

/// Failure while accepting a signed trusted context at the guest boundary.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum GuestBoundaryError {
    /// A verified context was already installed for this request.
    #[error("verified request context is already installed")]
    DuplicateContext,
    /// The request carried both a signed context and caller credentials.
    #[error("signed context and caller credentials are both present")]
    DuplicateAuthentication,
    /// Credentials arrived without a valid signed envelope.
    #[error("credentials arrived without a signed trusted context")]
    CredentialWithoutEnvelope,
    /// The envelope was missing a binding, expired, forged, or unsigned.
    #[error(transparent)]
    Rejected(TrustedContextError),
}

/// Removes every externally supplied internal identity header.
///
/// This includes the signed context header, every other `x-wasi-auth-*`
/// header, and the legacy session and admin-token headers. Header names are
/// matched case-insensitively.
pub fn strip_untrusted_auth_metadata(headers: &mut HeaderMap) {
    let reserved = headers
        .keys()
        .filter(|name| is_reserved_identity_header(name))
        .cloned()
        .collect::<Vec<_>>();
    for name in reserved {
        headers.remove(name);
    }
}

/// Removes caller credentials before a request is forwarded to the guest.
///
/// Authorization, proxy authorization, and session cookies are credentials.
/// Other cookies, including the CSRF cookie, are preserved. A cookie header
/// that is not visible UTF-8 is dropped so a hidden session cookie cannot be
/// forwarded.
pub fn strip_forwarded_credentials(headers: &mut HeaderMap) {
    headers.remove(AUTHORIZATION);
    headers.remove(PROXY_AUTHORIZATION);
    let cookies = headers.get_all(COOKIE).iter().cloned().collect::<Vec<_>>();
    headers.remove(COOKIE);
    for cookie in cookies {
        let Ok(text) = cookie.to_str() else {
            continue;
        };
        let kept = text
            .split(';')
            .map(str::trim)
            .filter(|part| !part.is_empty() && !is_session_cookie_pair(part))
            .collect::<Vec<_>>();
        let joined = kept.join("; ");
        if joined.is_empty() {
            continue;
        }
        if let Ok(value) = HeaderValue::from_str(&joined) {
            headers.append(COOKIE, value);
        }
    }
}

/// Installs one sensitive HMAC envelope and removes caller credentials.
///
/// Call this only after trusted ingress has authenticated the request. The
/// guest recovers authority with [`accept_signed_trusted_context`]. Portable
/// middleware context bytes are not accepted by that function.
///
/// # Errors
///
/// Returns [`TrustedContextError::InvalidEnvelope`] when `envelope` is empty,
/// oversized, or not a single header value.
pub fn install_signed_guest_context(
    headers: &mut HeaderMap,
    envelope: &str,
) -> Result<(), TrustedContextError> {
    let mut parts = envelope.split('.');
    let payload = parts.next().filter(|part| !part.is_empty());
    let signature = parts.next().filter(|part| !part.is_empty());
    if envelope.len() > MAX_TRUSTED_CONTEXT_HEADER_BYTES
        || payload.is_none()
        || signature.is_none()
        || parts.next().is_some()
        || envelope
            .bytes()
            .any(|byte| byte.is_ascii_whitespace() || !byte.is_ascii())
    {
        return Err(TrustedContextError::InvalidEnvelope);
    }
    let mut header =
        HeaderValue::from_str(envelope).map_err(|_| TrustedContextError::InvalidEnvelope)?;
    header.set_sensitive(true);
    strip_untrusted_auth_metadata(headers);
    strip_forwarded_credentials(headers);
    headers.insert(AUTH_CONTEXT_HEADER, header);
    Ok(())
}

/// Verifies one HMAC trusted-context envelope and installs it in extensions.
///
/// Forged headers, the unsigned portable-middleware context, expired or
/// rebound envelopes, duplicate contexts, and requests that still carry caller
/// credentials fail closed. Every path removes the wire header and caller
/// credentials so a later middleware cannot authenticate the request again.
///
/// `Ok(None)` is an anonymous request: no envelope and no caller credentials.
///
/// # Errors
///
/// Returns [`GuestBoundaryError`] without installing authority.
pub fn accept_signed_trusted_context<B>(
    codec: &TrustedContextCodec,
    request: &mut Request<B>,
    now_unix_seconds: u64,
) -> Result<Option<VerifiedRequestContext>, GuestBoundaryError> {
    if request
        .extensions()
        .get::<VerifiedRequestContext>()
        .is_some()
        || request.extensions().get::<VerifiedAuthContext>().is_some()
    {
        strip_identity_material(request.headers_mut());
        return Err(GuestBoundaryError::DuplicateContext);
    }
    let envelope = match single_text_header(request.headers(), &AUTH_CONTEXT_HEADER) {
        Ok(value) => value.map(str::to_owned),
        Err(error) => {
            strip_identity_material(request.headers_mut());
            return Err(GuestBoundaryError::Rejected(error));
        }
    };
    let credentials = has_forwarded_credential(request.headers());
    let Some(envelope) = envelope else {
        strip_identity_material(request.headers_mut());
        return if credentials {
            Err(GuestBoundaryError::CredentialWithoutEnvelope)
        } else {
            Ok(None)
        };
    };
    if credentials {
        strip_identity_material(request.headers_mut());
        return Err(GuestBoundaryError::DuplicateAuthentication);
    }
    let request_id = match single_text_header(request.headers(), &REQUEST_ID_HEADER) {
        Ok(Some(value)) => value.to_owned(),
        Ok(None) | Err(_) => {
            strip_identity_material(request.headers_mut());
            return Err(GuestBoundaryError::Rejected(
                TrustedContextError::BindingMismatch,
            ));
        }
    };
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let opened = codec.open(&envelope, &method, &path, &request_id, now_unix_seconds);
    strip_identity_material(request.headers_mut());
    let context = opened.map_err(GuestBoundaryError::Rejected)?;
    request.extensions_mut().insert(context.auth().clone());
    request.extensions_mut().insert(context.clone());
    Ok(Some(context))
}

/// Removes identity and credential headers echoed by a downstream response.
pub fn sanitize_downstream_response<B>(response: &mut Response<B>) {
    strip_untrusted_auth_metadata(response.headers_mut());
    response.headers_mut().remove(AUTHORIZATION);
    response.headers_mut().remove(PROXY_AUTHORIZATION);
    response.headers_mut().remove(COOKIE);
}

fn strip_identity_material(headers: &mut HeaderMap) {
    strip_untrusted_auth_metadata(headers);
    strip_forwarded_credentials(headers);
}

fn is_reserved_identity_header(name: &HeaderName) -> bool {
    let name = name.as_str();
    name.starts_with(RESERVED_AUTH_PREFIX)
        || name == LEGACY_SESSION_HEADER.as_str()
        || name == LEGACY_ADMIN_HEADER.as_str()
}

fn has_forwarded_credential(headers: &HeaderMap) -> bool {
    headers.contains_key(AUTHORIZATION)
        || headers.contains_key(PROXY_AUTHORIZATION)
        || cookie_header_has_session(headers)
}

fn cookie_header_has_session(headers: &HeaderMap) -> bool {
    headers.get_all(COOKIE).iter().any(|value| {
        value
            .to_str()
            .is_ok_and(|text| text.split(';').any(is_session_cookie_pair))
    })
}

fn is_session_cookie_pair(part: &str) -> bool {
    let name = part
        .trim()
        .split_once('=')
        .map(|(name, _)| name.trim())
        .unwrap_or("");
    name == HOST_SESSION_COOKIE || name == DEVELOPMENT_SESSION_COOKIE
}

fn single_text_header<'a>(
    headers: &'a HeaderMap,
    name: &HeaderName,
) -> Result<Option<&'a str>, TrustedContextError> {
    let mut values = headers.get_all(name).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(TrustedContextError::InvalidEnvelope);
    }
    value
        .to_str()
        .map(Some)
        .map_err(|_| TrustedContextError::InvalidEnvelope)
}

/// Applies mandatory no-store and browser security headers.
pub fn apply_secure_response_headers<B>(response: &mut Response<B>) {
    apply_response_security(response, ResponseSecurityPolicy::Sensitive, true);
}

/// Cache and transport policy for one response class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ResponseSecurityPolicy {
    /// Authentication, account, administration, and API responses.
    Sensitive,
    /// Server-rendered pages that must be revalidated.
    DynamicPage,
    /// Content-addressed static files safe for long-lived public caching.
    ImmutableAsset,
}

/// Applies route-specific cache and browser security headers.
///
/// A response that already carries a different referrer, CSP, nosniff, or
/// HSTS value is left untouched. Portable middleware uses
/// `strict-origin-when-cross-origin`; overwriting it with this crate's
/// `same-origin` policy would enforce two owners' rules on one response.
pub fn apply_response_security<B>(
    response: &mut Response<B>,
    policy: ResponseSecurityPolicy,
    secure_transport: bool,
) {
    if foreign_response_security(response.headers()) {
        return;
    }
    let headers = response.headers_mut();
    headers.insert(
        CACHE_CONTROL,
        match policy {
            ResponseSecurityPolicy::Sensitive => HeaderValue::from_static("no-store"),
            ResponseSecurityPolicy::DynamicPage => {
                HeaderValue::from_static("no-cache, must-revalidate")
            }
            ResponseSecurityPolicy::ImmutableAsset => {
                HeaderValue::from_static("public, max-age=31536000, immutable")
            }
        },
    );
    headers.insert(
        X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static(CANONICAL_CONTENT_TYPE_OPTIONS),
    );
    headers.insert(
        REFERRER_POLICY,
        HeaderValue::from_static(CANONICAL_REFERRER_POLICY),
    );
    if policy != ResponseSecurityPolicy::ImmutableAsset {
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static(CANONICAL_CONTENT_SECURITY_POLICY),
        );
    }
    if secure_transport {
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static(CANONICAL_HSTS),
        );
    } else {
        headers.remove(STRICT_TRANSPORT_SECURITY);
    }
}

/// Returns whether a response already has conflicting duplicate edge-security
/// or CORS headers.
///
/// One owner may set each policy header. A second appended value means two
/// policies were enforced and the response must be discarded.
#[must_use]
pub fn conflicting_edge_security_headers(headers: &HeaderMap) -> bool {
    [
        REFERRER_POLICY,
        CONTENT_SECURITY_POLICY,
        STRICT_TRANSPORT_SECURITY,
        X_CONTENT_TYPE_OPTIONS,
        ACCESS_CONTROL_ALLOW_ORIGIN,
        ACCESS_CONTROL_ALLOW_CREDENTIALS,
        ACCESS_CONTROL_ALLOW_METHODS,
        ACCESS_CONTROL_ALLOW_HEADERS,
    ]
    .into_iter()
    .any(|name| headers.get_all(name).iter().nth(1).is_some())
}

fn foreign_response_security(headers: &HeaderMap) -> bool {
    header_disagrees(headers, REFERRER_POLICY, CANONICAL_REFERRER_POLICY)
        || header_disagrees(
            headers,
            CONTENT_SECURITY_POLICY,
            CANONICAL_CONTENT_SECURITY_POLICY,
        )
        || header_disagrees(
            headers,
            X_CONTENT_TYPE_OPTIONS,
            CANONICAL_CONTENT_TYPE_OPTIONS,
        )
        || header_disagrees(headers, STRICT_TRANSPORT_SECURITY, CANONICAL_HSTS)
}

fn header_disagrees(headers: &HeaderMap, name: HeaderName, expected: &str) -> bool {
    headers
        .get_all(name)
        .iter()
        .any(|value| value.as_bytes() != expected.as_bytes())
}

/// Declared `Content-Length` violation.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum RequestBodyLimitError {
    /// The header was duplicated or not a decimal byte count.
    #[error("request body length is invalid")]
    Invalid,
    /// The declared length exceeds the route limit.
    #[error("request body exceeds its configured limit")]
    TooLarge,
}

/// Rejects a duplicated, malformed, or oversized declared body length.
///
/// A missing `Content-Length` is allowed. Callers that stream a body must
/// still count the bytes they forward.
pub fn enforce_declared_body_limit(
    headers: &HeaderMap,
    limit: usize,
) -> Result<(), RequestBodyLimitError> {
    let values = headers.get_all(CONTENT_LENGTH);
    let mut lengths = values.iter();
    let Some(value) = lengths.next() else {
        return Ok(());
    };
    if lengths.next().is_some() {
        return Err(RequestBodyLimitError::Invalid);
    }
    let length = value
        .to_str()
        .ok()
        .and_then(|text| text.parse::<usize>().ok())
        .ok_or(RequestBodyLimitError::Invalid)?;
    if length > limit {
        return Err(RequestBodyLimitError::TooLarge);
    }
    Ok(())
}

fn validate_content_length<E>(headers: &HeaderMap, limit: usize) -> Result<(), HttpBoundaryError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    enforce_declared_body_limit(headers, limit).map_err(|error| match error {
        RequestBodyLimitError::Invalid => HttpBoundaryError::InvalidContentLength,
        RequestBodyLimitError::TooLarge => HttpBoundaryError::BodyTooLarge,
    })
}

fn request_id<E>(headers: &HeaderMap) -> Result<RequestId, HttpBoundaryError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let mut values = headers.get_all(&REQUEST_ID_HEADER).iter();
    let Some(value) = values.next() else {
        return Err(HttpBoundaryError::InvalidRequestId);
    };
    if values.next().is_some() {
        return Err(HttpBoundaryError::InvalidRequestId);
    }
    RequestId::new(
        value
            .to_str()
            .map_err(|_| HttpBoundaryError::InvalidRequestId)?,
    )
    .map_err(|_| HttpBoundaryError::InvalidRequestId)
}

fn credential<E>(
    headers: &HeaderMap,
    allow_development_session_cookie: bool,
) -> Result<Option<Credential>, HttpBoundaryError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let authorization = headers.get_all(AUTHORIZATION);
    let mut authorization = authorization.iter();
    let bearer = authorization.next();
    if authorization.next().is_some() {
        return Err(HttpBoundaryError::InvalidCredentials);
    }
    let host_session_cookie = cookie_value(headers, HOST_SESSION_COOKIE)?;
    let development_session_cookie = if allow_development_session_cookie {
        cookie_value(headers, DEVELOPMENT_SESSION_COOKIE)?
    } else {
        None
    };
    if host_session_cookie.is_some() && development_session_cookie.is_some() {
        return Err(HttpBoundaryError::InvalidCredentials);
    }
    let session_cookie = host_session_cookie.or(development_session_cookie);
    if bearer.is_some() && session_cookie.is_some() {
        return Err(HttpBoundaryError::InvalidCredentials);
    }
    if let Some(value) = bearer {
        let value = value
            .to_str()
            .map_err(|_| HttpBoundaryError::InvalidCredentials)?;
        let token = value
            .strip_prefix("Bearer ")
            .filter(|token| !token.is_empty())
            .ok_or(HttpBoundaryError::InvalidCredentials)?;
        return Ok(Some(Credential::Bearer(token.to_owned())));
    }
    Ok(session_cookie.map(Credential::SessionCookie))
}

fn cookie_value<E>(headers: &HeaderMap, name: &str) -> Result<Option<String>, HttpBoundaryError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let mut found = None;
    for header in headers.get_all(COOKIE) {
        let header = header
            .to_str()
            .map_err(|_| HttpBoundaryError::InvalidCredentials)?;
        for cookie in header.split(';') {
            let Some((cookie_name, value)) = cookie.trim().split_once('=') else {
                continue;
            };
            if cookie_name == name {
                if found.is_some() || value.is_empty() {
                    return Err(HttpBoundaryError::InvalidCredentials);
                }
                found = Some(value.to_owned());
            }
        }
    }
    Ok(found)
}

fn requires_csrf(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

fn validate_csrf<E>(headers: &HeaderMap, allowed_origin: &str) -> Result<(), HttpBoundaryError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let origin = headers
        .get(ORIGIN)
        .and_then(|value| value.to_str().ok())
        .filter(|origin| *origin == allowed_origin)
        .ok_or(HttpBoundaryError::Csrf)?;
    if origin != allowed_origin {
        return Err(HttpBoundaryError::Csrf);
    }
    let header_token = headers
        .get(&CSRF_HEADER)
        .and_then(|value| value.to_str().ok())
        .ok_or(HttpBoundaryError::Csrf)?;
    let cookie_token = cookie_value(headers, "__Host-csrf")?.ok_or(HttpBoundaryError::Csrf)?;
    if header_token.len() < 32 || header_token.as_bytes() != cookie_token.as_bytes() {
        return Err(HttpBoundaryError::Csrf);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::context::{RoleId, UserId};

    #[derive(Debug, Error)]
    #[error("fixture error")]
    struct FixtureError;

    #[derive(Clone, Copy)]
    struct FixtureClock;

    impl Clock for FixtureClock {
        fn now_unix_seconds(&self) -> u64 {
            100
        }
    }

    #[derive(Clone, Copy)]
    struct FixtureAuthenticator;

    impl CredentialAuthenticator for FixtureAuthenticator {
        type Error = FixtureError;

        async fn authenticate(
            &self,
            _credential: &Credential,
        ) -> Result<AuthenticatedSession, Self::Error> {
            Ok(AuthenticatedSession {
                principal: Principal::new(
                    UserId::new("user-one").expect("valid fixture"),
                    "https://issuer.example",
                    false,
                )
                .expect("valid fixture"),
                organization_id: Some(
                    OrganizationId::new("organization-one").expect("valid fixture"),
                ),
                session_id: SessionId::new("session-one").expect("valid fixture"),
                assurance: AuthenticationAssurance::Aal1,
                issued_at_unix_seconds: 90,
                expires_at_unix_seconds: 200,
                decision_id: None,
                policy_revision: None,
                authorization: AuthorizationSnapshot::new(
                    ["document.read"],
                    [RoleId::new("reader").expect("valid fixture")],
                    None,
                    None,
                )
                .expect("valid fixture"),
            })
        }
    }

    #[test]
    fn credential_rejects_bearer_and_cookie_together() {
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer token")
            .header(COOKIE, "__Host-session=session")
            .body(())
            .expect("valid fixture");

        let result = credential::<FixtureError>(request.headers(), false);

        assert!(matches!(result, Err(HttpBoundaryError::InvalidCredentials)));
    }

    #[test]
    fn secure_headers_disable_response_caching() {
        let mut response = Response::new(());

        apply_secure_response_headers(&mut response);

        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static("no-store"))
        );
    }

    #[test]
    fn trusted_ingress_seals_identity_and_authorization_together() {
        let request = Request::builder()
            .header(AUTHORIZATION, "Bearer token")
            .header(REQUEST_ID_HEADER, "request-one")
            .body(())
            .expect("valid fixture");
        let ingress = TrustedIngress::new(
            TrustedIngressConfig::new("https://app.example").expect("valid fixture"),
            FixtureAuthenticator,
            FixtureClock,
        );

        let context = futures::executor::block_on(
            ingress.authenticate_request(&request, RoutePolicy::Authenticated),
        )
        .expect("trusted request")
        .expect("authenticated context");

        assert!(context.authorization().has_permission("document.read"));
    }

    #[test]
    fn signed_context_rejects_tampering_rebinding_and_replay() {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/authorization/check")
            .header(AUTHORIZATION, "Bearer token")
            .header(REQUEST_ID_HEADER, "request-signed")
            .body(())
            .expect("valid fixture");
        let ingress = TrustedIngress::new(
            TrustedIngressConfig::new("https://app.example").expect("valid fixture"),
            FixtureAuthenticator,
            FixtureClock,
        );
        let context = futures::executor::block_on(
            ingress.authenticate_request(&request, RoutePolicy::Authenticated),
        )
        .expect("trusted request")
        .expect("authenticated context");
        let codec = TrustedContextCodec::new("fullstack-app", [7; 32]).expect("valid codec");
        let envelope = codec
            .seal(&context, &Method::POST, "/api/authorization/check", 100)
            .expect("sealed context");

        let opened = codec
            .open(
                &envelope,
                &Method::POST,
                "/api/authorization/check",
                "request-signed",
                100,
            )
            .expect("opened context");
        assert_eq!(opened, context);

        let mut tampered = envelope.into_bytes();
        let last = tampered.last_mut().expect("signature byte");
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).expect("ASCII envelope");
        assert_eq!(
            codec.open(
                &tampered,
                &Method::POST,
                "/api/authorization/check",
                "request-signed",
                100,
            ),
            Err(TrustedContextError::InvalidEnvelope)
        );
        assert_eq!(
            codec.open(
                codec
                    .seal(&context, &Method::POST, "/api/authorization/check", 100,)
                    .expect("sealed context")
                    .as_str(),
                &Method::POST,
                "/api/authorization/batch-check",
                "request-signed",
                100,
            ),
            Err(TrustedContextError::BindingMismatch)
        );
        let envelope = codec
            .seal(&context, &Method::POST, "/api/authorization/check", 100)
            .expect("sealed context");
        assert_eq!(
            codec.open(
                &envelope,
                &Method::POST,
                "/api/authorization/check",
                "request-signed",
                106,
            ),
            Err(TrustedContextError::Expired)
        );
    }

    #[test]
    fn immutable_assets_keep_cacheability_without_localhost_hsts() {
        let mut response = Response::new(());

        apply_response_security(&mut response, ResponseSecurityPolicy::ImmutableAsset, false);

        assert_eq!(
            response.headers().get(CACHE_CONTROL),
            Some(&HeaderValue::from_static(
                "public, max-age=31536000, immutable"
            ))
        );
        assert!(!response.headers().contains_key(STRICT_TRANSPORT_SECURITY));
    }

    #[test]
    fn debug_forms_omit_the_session_identifier() {
        let (_, context, _) = sealed_context();
        let rendered = format!("{context:?}");
        assert!(!rendered.contains("session-one"));
        assert!(!rendered.contains(context.auth().session_id().as_str()));
        assert_eq!(
            format!("{:?}", context.auth().session_id()),
            "SessionId([REDACTED])"
        );
    }

    #[test]
    fn spin_envelopes_can_be_exported_for_the_host_probe() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs();
        let auth = VerifiedAuthContext::from_validated(ValidatedContextParts {
            principal: Principal::new(
                UserId::new("user-one").expect("valid fixture"),
                "https://issuer.example",
                false,
            )
            .expect("valid fixture"),
            organization_id: Some(OrganizationId::new("organization-one").expect("valid fixture")),
            session_id: SessionId::new("session-one").expect("valid fixture"),
            request_id: RequestId::new("request-spin").expect("valid fixture"),
            assurance: AuthenticationAssurance::Aal1,
            issued_at_unix_seconds: now.saturating_sub(10),
            expires_at_unix_seconds: now.saturating_add(3_600),
            decision_id: None,
            policy_revision: None,
        })
        .expect("valid context");
        let context = VerifiedRequestContext::from_verified(
            auth,
            AuthorizationSnapshot::new(
                ["document.read"],
                [RoleId::new("reader").expect("valid fixture")],
                None,
                None,
            )
            .expect("valid snapshot"),
        );
        let codec = TrustedContextCodec::new("fullstack-app", [7; 32])
            .expect("valid codec")
            .with_max_age_seconds(30)
            .expect("max age");
        let valid = codec
            .seal(&context, &Method::GET, "/guest", now)
            .expect("valid envelope");
        let expired = codec
            .seal(&context, &Method::GET, "/guest", now.saturating_sub(120))
            .expect("expired envelope");
        assert!(valid.contains('.'));
        assert_ne!(valid, expired);
        let Ok(path) = std::env::var("SPIN_ENVELOPE_OUT") else {
            return;
        };
        let mut tampered = valid.clone().into_bytes();
        let last = tampered.last_mut().expect("signature byte");
        *last = if *last == b'A' { b'B' } else { b'A' };
        let tampered = String::from_utf8(tampered).expect("ascii envelope");
        std::fs::write(
            path,
            format!("valid {valid}\nexpired {expired}\ntampered {tampered}\n"),
        )
        .expect("envelope file");
    }

    fn sealed_context() -> (TrustedContextCodec, VerifiedRequestContext, String) {
        let request = Request::builder()
            .method(Method::POST)
            .uri("/api/authorization/check")
            .header(AUTHORIZATION, "Bearer token")
            .header(REQUEST_ID_HEADER, "request-signed")
            .body(())
            .expect("valid fixture");
        let ingress = TrustedIngress::new(
            TrustedIngressConfig::new("https://app.example").expect("valid fixture"),
            FixtureAuthenticator,
            FixtureClock,
        );
        let context = futures::executor::block_on(
            ingress.authenticate_request(&request, RoutePolicy::Authenticated),
        )
        .expect("trusted request")
        .expect("authenticated context");
        let codec = TrustedContextCodec::new("fullstack-app", [7; 32]).expect("valid codec");
        let envelope = codec
            .seal(&context, &Method::POST, "/api/authorization/check", 100)
            .expect("sealed context");
        (codec, context, envelope)
    }

    fn portable_middleware_context() -> String {
        let json = r#"{"version":1,"state":"authenticated","service_id":"orders","audiences":["api://orders"],"principal":{"issuer":"https://idp.example","subject":"admin","roles":["owner"],"scopes":["document.write"]},"decision_id":"decision-forged","policy_revision":"forged"}"#;
        URL_SAFE_NO_PAD.encode(json)
    }

    #[test]
    fn forged_identity_headers_are_stripped_and_do_not_grant_authority() {
        let (codec, _, _) = sealed_context();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/authorization/check")
            .header(REQUEST_ID_HEADER, "request-signed")
            .header("x-wasi-auth-subject", "admin")
            .header("x-auth-admin-token", "forged-admin")
            .header("x-auth-session", "forged-session")
            .body(())
            .expect("valid fixture");
        let mixed_case = HeaderName::from_bytes(b"X-Wasi-Auth-Role").expect("valid header");
        request
            .headers_mut()
            .insert(mixed_case.clone(), HeaderValue::from_static("owner"));

        let accepted = accept_signed_trusted_context(&codec, &mut request, 100);

        assert_eq!(accepted, Ok(None));
        assert!(request.extensions().get::<VerifiedAuthContext>().is_none());
        assert!(
            request
                .extensions()
                .get::<VerifiedRequestContext>()
                .is_none()
        );
        assert!(!request.headers().contains_key("x-wasi-auth-subject"));
        assert!(!request.headers().contains_key(mixed_case));
        assert!(!request.headers().contains_key("x-auth-admin-token"));
        assert!(!request.headers().contains_key("x-auth-session"));
    }

    #[test]
    fn portable_middleware_context_is_not_a_signed_wasi_auth_context() {
        let (codec, context, envelope) = sealed_context();
        let portable = portable_middleware_context();
        assert!(
            !portable.contains('.'),
            "portable context is unsigned base64url JSON"
        );
        assert!(
            envelope.contains('.'),
            "signed context is payload.signature"
        );
        assert_ne!(portable, envelope);
        let mut headers = HeaderMap::new();
        assert_eq!(
            install_signed_guest_context(&mut headers, &portable),
            Err(TrustedContextError::InvalidEnvelope)
        );
        assert!(!headers.contains_key(AUTH_CONTEXT_HEADER));

        assert_eq!(
            codec.open(
                &portable,
                &Method::POST,
                "/api/authorization/check",
                "request-signed",
                100,
            ),
            Err(TrustedContextError::InvalidEnvelope)
        );
        let forged_signature = format!("{portable}.AAAA");
        assert_eq!(
            codec.open(
                &forged_signature,
                &Method::POST,
                "/api/authorization/check",
                "request-signed",
                100,
            ),
            Err(TrustedContextError::InvalidEnvelope)
        );

        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/authorization/check")
            .header(REQUEST_ID_HEADER, "request-signed")
            .header(AUTH_CONTEXT_HEADER, &portable)
            .body(())
            .expect("valid fixture");
        let accepted = accept_signed_trusted_context(&codec, &mut request, 100);
        assert_eq!(
            accepted,
            Err(GuestBoundaryError::Rejected(
                TrustedContextError::InvalidEnvelope
            ))
        );
        assert!(request.extensions().get::<VerifiedAuthContext>().is_none());
        assert!(!request.headers().contains_key(AUTH_CONTEXT_HEADER));
        assert_ne!(
            context.auth().principal().user_id().as_str(),
            "admin",
            "the forged portable subject must not become the verified principal"
        );
    }

    #[test]
    fn signed_context_accepts_once_and_fails_closed_on_expiry_rebind_and_replay() {
        let (codec, context, envelope) = sealed_context();
        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/authorization/check?ignored=1")
            .header(REQUEST_ID_HEADER, "request-signed")
            .header(AUTHORIZATION, "Bearer token")
            .header(COOKIE, "__Host-session=session-secret; theme=light")
            .header(AUTH_CONTEXT_HEADER, &envelope)
            .body(())
            .expect("valid fixture");

        assert_eq!(
            accept_signed_trusted_context(&codec, &mut request, 100),
            Err(GuestBoundaryError::DuplicateAuthentication)
        );
        assert!(
            request
                .extensions()
                .get::<VerifiedRequestContext>()
                .is_none()
        );
        assert!(!request.headers().contains_key(AUTHORIZATION));
        assert!(!request.headers().contains_key(AUTH_CONTEXT_HEADER));

        let mut request = Request::builder()
            .method(Method::POST)
            .uri("/api/authorization/check")
            .header(REQUEST_ID_HEADER, "request-signed")
            .header(AUTH_CONTEXT_HEADER, &envelope)
            .body(())
            .expect("valid fixture");
        let accepted = accept_signed_trusted_context(&codec, &mut request, 100)
            .expect("signed context")
            .expect("authenticated context");
        assert_eq!(accepted, context);
        assert_eq!(
            request.extensions().get::<VerifiedRequestContext>(),
            Some(&context)
        );
        assert!(!request.headers().contains_key(AUTH_CONTEXT_HEADER));
        assert!(
            format!("{accepted:?}").contains("[REDACTED]"),
            "session identifier must not appear in debug output"
        );
        assert!(!format!("{accepted:?}").contains("session-one"));

        assert_eq!(
            accept_signed_trusted_context(&codec, &mut request, 100),
            Err(GuestBoundaryError::DuplicateContext)
        );
        assert_eq!(
            request.extensions().get::<VerifiedRequestContext>(),
            Some(&context)
        );

        let mut rebound = Request::builder()
            .method(Method::POST)
            .uri("/api/authorization/check")
            .header(REQUEST_ID_HEADER, "request-replayed")
            .header(AUTH_CONTEXT_HEADER, &envelope)
            .body(())
            .expect("valid fixture");
        assert_eq!(
            accept_signed_trusted_context(&codec, &mut rebound, 100),
            Err(GuestBoundaryError::Rejected(
                TrustedContextError::BindingMismatch
            ))
        );
        assert!(rebound.extensions().get::<VerifiedAuthContext>().is_none());

        let mut expired = Request::builder()
            .method(Method::POST)
            .uri("/api/authorization/check")
            .header(REQUEST_ID_HEADER, "request-signed")
            .header(AUTH_CONTEXT_HEADER, &envelope)
            .body(())
            .expect("valid fixture");
        assert_eq!(
            accept_signed_trusted_context(&codec, &mut expired, 106),
            Err(GuestBoundaryError::Rejected(TrustedContextError::Expired))
        );
        assert!(expired.extensions().get::<VerifiedAuthContext>().is_none());
        assert_eq!(
            codec.open(
                &envelope,
                &Method::POST,
                "/api/authorization/check",
                "request-signed",
                105,
            ),
            Ok(context.clone()),
            "the same binding is valid through the configured max age"
        );
        assert_eq!(
            codec.open(
                &envelope,
                &Method::POST,
                "/api/authorization/check",
                "request-signed",
                98,
            ),
            Err(TrustedContextError::Expired),
            "a context sealed more than one second in the future is rejected"
        );
        let other_key = TrustedContextCodec::new("fullstack-app", [9; 32]).expect("valid codec");
        assert_eq!(
            other_key.open(
                &envelope,
                &Method::POST,
                "/api/authorization/check",
                "request-signed",
                100,
            ),
            Err(TrustedContextError::InvalidEnvelope)
        );
    }

    #[test]
    fn guest_install_strips_credentials_and_marks_the_envelope_sensitive() {
        let (_, _, envelope) = sealed_context();
        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, HeaderValue::from_static("Bearer token"));
        headers.insert(
            COOKIE,
            HeaderValue::from_static("__Host-session=secret; theme=light"),
        );
        headers.insert("x-wasi-auth-subject", HeaderValue::from_static("admin"));

        install_signed_guest_context(&mut headers, &envelope).expect("install envelope");

        let installed = headers.get(AUTH_CONTEXT_HEADER).expect("signed header");
        assert_eq!(installed.to_str().expect("text"), envelope);
        assert!(installed.is_sensitive());
        assert!(!headers.contains_key(AUTHORIZATION));
        assert!(!headers.contains_key("x-wasi-auth-subject"));
        assert_eq!(
            headers.get(COOKIE).and_then(|value| value.to_str().ok()),
            Some("theme=light")
        );
        assert_eq!(
            format!("{:?}", Credential::Bearer("token".to_owned())),
            "Bearer([REDACTED])"
        );
    }

    #[test]
    fn credentials_without_an_envelope_fail_closed() {
        let (codec, _, _) = sealed_context();
        let mut request = Request::builder()
            .header(AUTHORIZATION, "Bearer token")
            .body(())
            .expect("valid fixture");

        assert_eq!(
            accept_signed_trusted_context(&codec, &mut request, 100),
            Err(GuestBoundaryError::CredentialWithoutEnvelope)
        );
        assert!(!request.headers().contains_key(AUTHORIZATION));
        assert!(request.extensions().get::<VerifiedAuthContext>().is_none());
    }

    #[test]
    fn downstream_responses_do_not_echo_identity_headers() {
        let mut response = Response::builder()
            .header(AUTH_CONTEXT_HEADER, "payload.signature")
            .header(AUTHORIZATION, "Bearer token")
            .header(COOKIE, "__Host-session=secret")
            .header("x-wasi-auth-subject", "admin")
            .header(
                http::header::SET_COOKIE,
                "__Host-session=next; Secure; HttpOnly",
            )
            .body(())
            .expect("valid fixture");

        sanitize_downstream_response(&mut response);

        assert!(!response.headers().contains_key(AUTH_CONTEXT_HEADER));
        assert!(!response.headers().contains_key(AUTHORIZATION));
        assert!(!response.headers().contains_key(COOKIE));
        assert!(!response.headers().contains_key("x-wasi-auth-subject"));
        assert!(response.headers().contains_key(http::header::SET_COOKIE));
    }

    #[test]
    fn cors_and_security_headers_do_not_overwrite_a_foreign_policy() {
        let config = CorsConfig::new(["https://app.example"], ["GET"], ["content-type"], true)
            .expect("valid cors");
        let mut response = Response::new(());
        response.headers_mut().insert(
            ACCESS_CONTROL_ALLOW_ORIGIN,
            HeaderValue::from_static("https://middleware.example"),
        );
        let request = Request::builder()
            .header(ORIGIN, "https://app.example")
            .body(())
            .expect("valid fixture");

        assert!(!config.apply(request.headers(), &mut response));
        assert_eq!(
            response.headers().get(ACCESS_CONTROL_ALLOW_ORIGIN),
            Some(&HeaderValue::from_static("https://middleware.example"))
        );
        assert!(
            !response
                .headers()
                .contains_key(ACCESS_CONTROL_ALLOW_CREDENTIALS)
        );

        response.headers_mut().insert(
            REFERRER_POLICY,
            HeaderValue::from_static("strict-origin-when-cross-origin"),
        );
        apply_response_security(&mut response, ResponseSecurityPolicy::Sensitive, true);
        assert_eq!(
            response.headers().get(REFERRER_POLICY),
            Some(&HeaderValue::from_static("strict-origin-when-cross-origin"))
        );
        assert!(!response.headers().contains_key(CONTENT_SECURITY_POLICY));
        assert!(!response.headers().contains_key(CACHE_CONTROL));

        response
            .headers_mut()
            .append(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
        assert!(conflicting_edge_security_headers(response.headers()));
    }

    #[test]
    fn declared_body_limit_rejects_duplicates_and_oversized_lengths() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("4"));
        assert_eq!(
            enforce_declared_body_limit(&headers, 8),
            Err(RequestBodyLimitError::Invalid)
        );
        headers = HeaderMap::new();
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("9"));
        assert_eq!(
            enforce_declared_body_limit(&headers, 8),
            Err(RequestBodyLimitError::TooLarge)
        );
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("8"));
        assert_eq!(enforce_declared_body_limit(&headers, 8), Ok(()));
    }
}
