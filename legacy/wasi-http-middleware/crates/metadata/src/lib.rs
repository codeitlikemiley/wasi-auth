//! Trusted metadata shared by WASI HTTP middleware and terminal services.
//!
//! The metadata in this crate is trustworthy only when an application is
//! reachable exclusively through a composed middleware chain that removes
//! client-supplied values before inserting one canonical context.

use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::{HeaderMap, HeaderName, HeaderValue};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Request correlation header used by the middleware chain.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
/// Canonical header carrying the versioned authentication context.
pub const AUTH_CONTEXT_HEADER: HeaderName = HeaderName::from_static("x-wasi-auth-context");
/// Current authentication-context wire version.
pub const AUTH_CONTEXT_VERSION: u8 = 1;
/// Maximum encoded size accepted for [`AUTH_CONTEXT_HEADER`].
pub const MAX_AUTH_CONTEXT_ENCODED_LEN: usize = 8 * 1024;

const RESERVED_AUTH_PREFIX: &str = "x-wasi-auth-";
const MAX_IDENTITY_VALUE_LEN: usize = 512;
const MAX_CONTEXT_VALUE_LEN: usize = 256;
const MAX_SESSION_VALUE_LEN: usize = 512;
const MAX_COLLECTION_ITEMS: usize = 64;
const MAX_AUDIENCES: usize = 16;
const MAX_SCOPE_VALUE_LEN: usize = 2_048;

/// Authentication state represented by an [`AuthContextV1`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthStateV1 {
    /// No credential was supplied in optional-authentication mode.
    Anonymous,
    /// A credential was validated by the configured authentication broker.
    Authenticated,
}

/// Validated delegated actor identity.
///
/// Actor identity is always the ordered pair `(issuer, subject)`. It is not a
/// globally ambiguous subject string and is distinct from the authenticated
/// principal that is acting.
#[derive(Clone, Eq, PartialEq)]
pub struct ActorV1 {
    issuer: String,
    subject: String,
}

impl fmt::Debug for ActorV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ActorV1")
            .field("identity", &"<redacted>")
            .finish()
    }
}

impl ActorV1 {
    /// Constructs an actor with an issuer-scoped subject.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] when either identity field is empty, too
    /// large, ambiguous, or contains control characters.
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, MetadataError> {
        let issuer = issuer.into();
        let subject = subject.into();
        validate_text("actor.issuer", &issuer, MAX_IDENTITY_VALUE_LEN)?;
        validate_text("actor.subject", &subject, MAX_IDENTITY_VALUE_LEN)?;
        Ok(Self { issuer, subject })
    }

    /// Returns the canonical `(issuer, subject)` actor identity key.
    pub fn identity_key(&self) -> (&str, &str) {
        (&self.issuer, &self.subject)
    }

    /// Returns the actor issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the issuer-scoped actor subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }
}

/// Validated authenticated identity in an [`AuthContextV1`].
///
/// The canonical identity key is the ordered pair `(issuer, subject)`. A
/// subject must never be compared without its issuer.
#[derive(Clone, Eq, PartialEq)]
pub struct PrincipalV1 {
    issuer: String,
    subject: String,
    tenant_id: Option<String>,
    roles: Vec<String>,
    scopes: Vec<String>,
    acr: Option<String>,
    amr: Vec<String>,
    actor: Option<ActorV1>,
    auth_time: Option<u64>,
    expires_at: Option<u64>,
    session_id: Option<String>,
}

impl fmt::Debug for PrincipalV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PrincipalV1")
            .field("identity", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl PrincipalV1 {
    /// Constructs a principal with the canonical `(issuer, subject)` identity.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] when either identity field is empty, too
    /// large, ambiguous, or contains control characters.
    pub fn new(
        issuer: impl Into<String>,
        subject: impl Into<String>,
    ) -> Result<Self, MetadataError> {
        let issuer = issuer.into();
        let subject = subject.into();
        validate_text("issuer", &issuer, MAX_IDENTITY_VALUE_LEN)?;
        validate_text("subject", &subject, MAX_IDENTITY_VALUE_LEN)?;
        Ok(Self {
            issuer,
            subject,
            tenant_id: None,
            roles: Vec::new(),
            scopes: Vec::new(),
            acr: None,
            amr: Vec::new(),
            actor: None,
            auth_time: None,
            expires_at: None,
            session_id: None,
        })
    }

    /// Sets the optional tenant identifier.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] for an unsafe or oversized value.
    pub fn with_tenant_id(
        mut self,
        tenant_id: Option<impl Into<String>>,
    ) -> Result<Self, MetadataError> {
        self.tenant_id = tenant_id.map(Into::into);
        if let Some(value) = &self.tenant_id {
            validate_text("tenant_id", value, MAX_IDENTITY_VALUE_LEN)?;
        }
        Ok(self)
    }

    /// Sets canonical role tokens.
    ///
    /// Values are sorted and de-duplicated so the encoded context is
    /// deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] for invalid or excessive role tokens.
    pub fn with_roles(
        mut self,
        roles: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, MetadataError> {
        self.roles = validated_tokens("roles", roles)?;
        Ok(self)
    }

    /// Sets canonical OAuth scope tokens.
    ///
    /// Values are sorted and de-duplicated so the encoded context is
    /// deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] for invalid or excessive scope tokens.
    pub fn with_scopes(
        mut self,
        scopes: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, MetadataError> {
        self.scopes = validated_tokens("scopes", scopes)?;
        let encoded_len = self.scopes.iter().map(String::len).sum::<usize>()
            + self.scopes.len().saturating_sub(1);
        if encoded_len > MAX_SCOPE_VALUE_LEN {
            return Err(MetadataError::InvalidCollection { field: "scopes" });
        }
        Ok(self)
    }

    /// Sets the optional authentication context class reference (ACR).
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] for an unsafe or oversized value.
    pub fn with_acr(mut self, acr: Option<impl Into<String>>) -> Result<Self, MetadataError> {
        self.acr = acr.map(Into::into);
        if let Some(value) = &self.acr {
            validate_text("acr", value, MAX_CONTEXT_VALUE_LEN)?;
        }
        Ok(self)
    }

    /// Sets canonical authentication method reference (AMR) tokens.
    ///
    /// Values are sorted and de-duplicated so the encoded context is
    /// deterministic.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] for invalid or excessive AMR tokens.
    pub fn with_amr(
        mut self,
        amr: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, MetadataError> {
        self.amr = validated_tokens("amr", amr)?;
        Ok(self)
    }

    /// Sets an optional delegated actor with its own issuer-scoped identity.
    #[must_use]
    pub fn with_actor(mut self, actor: Option<ActorV1>) -> Self {
        self.actor = actor;
        self
    }

    /// Sets authentication and expiration Unix timestamps in seconds.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] when expiration is not later than the
    /// authentication time.
    pub fn with_times(
        mut self,
        auth_time: Option<u64>,
        expires_at: Option<u64>,
    ) -> Result<Self, MetadataError> {
        if auth_time
            .zip(expires_at)
            .is_some_and(|(auth, expiry)| expiry <= auth)
        {
            return Err(MetadataError::InvalidTimeRange);
        }
        self.auth_time = auth_time;
        self.expires_at = expires_at;
        Ok(self)
    }

    /// Sets the optional broker session identifier.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] for an unsafe or oversized value.
    pub fn with_session_id(
        mut self,
        session_id: Option<impl Into<String>>,
    ) -> Result<Self, MetadataError> {
        self.session_id = session_id.map(Into::into);
        if let Some(value) = &self.session_id {
            validate_text("session_id", value, MAX_SESSION_VALUE_LEN)?;
        }
        Ok(self)
    }

    /// Returns the canonical `(issuer, subject)` identity key.
    pub fn identity_key(&self) -> (&str, &str) {
        (&self.issuer, &self.subject)
    }

    /// Returns the trusted issuer.
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Returns the issuer-scoped subject.
    pub fn subject(&self) -> &str {
        &self.subject
    }

    /// Returns the optional tenant identifier.
    pub fn tenant_id(&self) -> Option<&str> {
        self.tenant_id.as_deref()
    }

    /// Returns canonical role tokens.
    pub fn roles(&self) -> &[String] {
        &self.roles
    }

    /// Returns canonical OAuth scope tokens.
    pub fn scopes(&self) -> &[String] {
        &self.scopes
    }

    /// Returns the optional authentication context class reference.
    pub fn acr(&self) -> Option<&str> {
        self.acr.as_deref()
    }

    /// Returns canonical authentication method reference tokens.
    pub fn amr(&self) -> &[String] {
        &self.amr
    }

    /// Returns the optional delegated actor identity.
    pub fn actor(&self) -> Option<&ActorV1> {
        self.actor.as_ref()
    }

    /// Returns the authentication Unix timestamp in seconds.
    pub fn auth_time(&self) -> Option<u64> {
        self.auth_time
    }

    /// Returns the expiration Unix timestamp in seconds.
    pub fn expires_at(&self) -> Option<u64> {
        self.expires_at
    }

    /// Returns the optional broker session identifier.
    pub fn session_id(&self) -> Option<&str> {
        self.session_id.as_deref()
    }
}

/// Version-one trusted authentication context.
///
/// `service_id` and `audiences` are deployment configuration, never values
/// accepted from the authentication broker. The terminal service identity and
/// expected OAuth audiences are distinct immutable values; for example,
/// `orders-api` may require the audience `api://orders`.
#[derive(Clone, Eq, PartialEq)]
pub struct AuthContextV1 {
    state: AuthStateV1,
    service_id: String,
    audiences: Vec<String>,
    principal: Option<PrincipalV1>,
    decision_id: Option<String>,
    policy_revision: Option<String>,
}

/// Authentication context validated by a trusted ingress or broker boundary.
///
/// This type is intended for storage in [`http::Extensions`]. Unlike the wire
/// header, it is not serialized when a request or response is reconstructed.
#[derive(Clone, Eq, PartialEq)]
pub struct VerifiedAuthContext(AuthContextV1);

impl fmt::Debug for VerifiedAuthContext {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("VerifiedAuthContext")
            .field("state", &self.0.state())
            .field("trusted_metadata", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl VerifiedAuthContext {
    /// Marks a context as verified by the current process trust boundary.
    ///
    /// Callers must only use this after validating the context's source,
    /// service binding, audience, and lifetime.
    #[must_use]
    pub fn new(context: AuthContextV1) -> Self {
        Self(context)
    }

    /// Returns the verified authentication context.
    #[must_use]
    pub fn context(&self) -> &AuthContextV1 {
        &self.0
    }

    /// Consumes the wrapper and returns the authentication context.
    #[must_use]
    pub fn into_inner(self) -> AuthContextV1 {
        self.0
    }
}

impl fmt::Debug for AuthContextV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthContextV1")
            .field("state", &self.state)
            .field("trusted_metadata", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl AuthContextV1 {
    /// Constructs an anonymous context for optional-authentication mode.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] for invalid deployment identity or audience
    /// configuration.
    pub fn anonymous(
        service_id: impl Into<String>,
        audiences: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, MetadataError> {
        let (service_id, audiences) = validated_deployment(service_id.into(), audiences)?;
        Ok(Self {
            state: AuthStateV1::Anonymous,
            service_id,
            audiences,
            principal: None,
            decision_id: None,
            policy_revision: None,
        })
    }

    /// Constructs an authenticated context from broker-validated identity.
    ///
    /// The caller must supply `service_id` and `audiences` from immutable
    /// middleware configuration, not from a broker response.
    ///
    /// # Errors
    ///
    /// Returns [`MetadataError`] for invalid deployment identity, audiences,
    /// decision identifier, or policy revision.
    pub fn authenticated(
        service_id: impl Into<String>,
        audiences: impl IntoIterator<Item = impl Into<String>>,
        principal: PrincipalV1,
        decision_id: impl Into<String>,
        policy_revision: impl Into<String>,
    ) -> Result<Self, MetadataError> {
        let (service_id, audiences) = validated_deployment(service_id.into(), audiences)?;
        let decision_id = decision_id.into();
        let policy_revision = policy_revision.into();
        validate_text("decision_id", &decision_id, MAX_CONTEXT_VALUE_LEN)?;
        validate_text("policy_revision", &policy_revision, MAX_CONTEXT_VALUE_LEN)?;
        Ok(Self {
            state: AuthStateV1::Authenticated,
            service_id,
            audiences,
            principal: Some(principal),
            decision_id: Some(decision_id),
            policy_revision: Some(policy_revision),
        })
    }

    /// Returns the authentication state.
    pub fn state(&self) -> AuthStateV1 {
        self.state
    }

    /// Returns the immutable terminal-service identifier.
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    /// Returns immutable configured audiences.
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    /// Returns the authenticated principal, if authentication occurred.
    pub fn principal(&self) -> Option<&PrincipalV1> {
        self.principal.as_ref()
    }

    /// Returns the authentication-broker decision identifier.
    pub fn decision_id(&self) -> Option<&str> {
        self.decision_id.as_deref()
    }

    /// Returns the authentication policy revision.
    pub fn policy_revision(&self) -> Option<&str> {
        self.policy_revision.as_deref()
    }
}

/// Errors produced while validating trusted identity metadata.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum MetadataError {
    /// A text value was empty, too long, ambiguous, or contained controls.
    #[error("invalid authentication field: {field}")]
    InvalidText {
        /// Name of the invalid field.
        field: &'static str,
    },
    /// A bounded list contained invalid or excessive values.
    #[error("invalid authentication collection: {field}")]
    InvalidCollection {
        /// Name of the invalid collection.
        field: &'static str,
    },
    /// An expiration timestamp did not follow its authentication timestamp.
    #[error("invalid authentication time range")]
    InvalidTimeRange,
    /// A canonical header appeared more than once.
    #[error("duplicate trusted metadata header: {0}")]
    DuplicateHeader(&'static str),
    /// A required canonical header was absent.
    #[error("missing trusted metadata header: {0}")]
    MissingHeader(&'static str),
    /// The encoded context exceeded its fixed size limit.
    #[error("authentication context exceeds the encoded size limit")]
    ContextTooLarge,
    /// The context was not canonical base64url without padding.
    #[error("authentication context has invalid base64url encoding")]
    InvalidEncoding,
    /// The decoded JSON did not match the strict V1 schema.
    #[error("authentication context has an invalid V1 schema")]
    InvalidSchema,
    /// The wire version is unsupported.
    #[error("unsupported authentication context version: {0}")]
    UnsupportedVersion(u8),
}

/// Removes every header reserved for trusted authentication metadata.
pub fn strip_reserved_auth_headers(headers: &mut HeaderMap) {
    let reserved = headers
        .keys()
        .filter(|name| name.as_str().starts_with(RESERVED_AUTH_PREFIX))
        .cloned()
        .collect::<Vec<_>>();
    for name in reserved {
        headers.remove(name);
    }
}

/// Encodes a validated context as canonical base64url JSON without padding.
///
/// # Errors
///
/// Returns [`MetadataError::ContextTooLarge`] if the encoded context exceeds
/// [`MAX_AUTH_CONTEXT_ENCODED_LEN`].
pub fn encode_auth_context(context: &AuthContextV1) -> Result<HeaderValue, MetadataError> {
    let wire = WireContextRef::from(context);
    let json = serde_json::to_vec(&wire).map_err(|_| MetadataError::InvalidSchema)?;
    let encoded = URL_SAFE_NO_PAD.encode(json);
    if encoded.len() > MAX_AUTH_CONTEXT_ENCODED_LEN {
        return Err(MetadataError::ContextTooLarge);
    }
    let mut value = HeaderValue::from_str(&encoded).map_err(|_| MetadataError::InvalidEncoding)?;
    value.set_sensitive(true);
    Ok(value)
}

/// Decodes and validates a canonical V1 authentication context.
///
/// The decoder rejects padding, non-canonical base64url, unknown JSON fields,
/// inconsistent authentication state, and every configured field bound.
///
/// # Errors
///
/// Returns [`MetadataError`] when the value is malformed or violates the V1
/// contract.
pub fn decode_auth_context(value: &HeaderValue) -> Result<AuthContextV1, MetadataError> {
    let encoded = value.to_str().map_err(|_| MetadataError::InvalidEncoding)?;
    if encoded.is_empty() || encoded.len() > MAX_AUTH_CONTEXT_ENCODED_LEN {
        return Err(if encoded.len() > MAX_AUTH_CONTEXT_ENCODED_LEN {
            MetadataError::ContextTooLarge
        } else {
            MetadataError::InvalidEncoding
        });
    }
    let decoded = URL_SAFE_NO_PAD
        .decode(encoded)
        .map_err(|_| MetadataError::InvalidEncoding)?;
    if URL_SAFE_NO_PAD.encode(&decoded) != encoded {
        return Err(MetadataError::InvalidEncoding);
    }
    let wire = serde_json::from_slice::<WireContextOwned>(&decoded)
        .map_err(|_| MetadataError::InvalidSchema)?;
    wire.try_into()
}

/// Replaces all reserved headers with one canonical authentication context.
///
/// # Errors
///
/// Returns [`MetadataError`] when the context cannot be encoded within the
/// fixed header bound.
pub fn insert_auth_context(
    headers: &mut HeaderMap,
    context: &AuthContextV1,
) -> Result<(), MetadataError> {
    let value = encode_auth_context(context)?;
    strip_reserved_auth_headers(headers);
    headers.insert(AUTH_CONTEXT_HEADER, value);
    Ok(())
}

/// Parses exactly one canonical authentication-context header.
///
/// # Errors
///
/// Returns [`MetadataError`] for missing, duplicate, malformed, or invalid
/// contexts.
pub fn parse_auth_context(headers: &HeaderMap) -> Result<AuthContextV1, MetadataError> {
    let mut values = headers.get_all(&AUTH_CONTEXT_HEADER).iter();
    let value = values
        .next()
        .ok_or(MetadataError::MissingHeader("auth_context"))?;
    if values.next().is_some() {
        return Err(MetadataError::DuplicateHeader("auth_context"));
    }
    decode_auth_context(value)
}

fn validated_deployment(
    service_id: String,
    audiences: impl IntoIterator<Item = impl Into<String>>,
) -> Result<(String, Vec<String>), MetadataError> {
    if !is_token(&service_id) {
        return Err(MetadataError::InvalidText {
            field: "service_id",
        });
    }
    let mut audiences = audiences.into_iter().map(Into::into).collect::<Vec<_>>();
    if audiences.is_empty() || audiences.len() > MAX_AUDIENCES {
        return Err(MetadataError::InvalidCollection { field: "audiences" });
    }
    for audience in &audiences {
        validate_ascii_text("audience", audience, MAX_CONTEXT_VALUE_LEN)?;
    }
    audiences.sort_unstable();
    audiences.dedup();
    Ok((service_id, audiences))
}

fn validated_tokens(
    field: &'static str,
    values: impl IntoIterator<Item = impl Into<String>>,
) -> Result<Vec<String>, MetadataError> {
    let mut values = values.into_iter().map(Into::into).collect::<Vec<_>>();
    if values.len() > MAX_COLLECTION_ITEMS || values.iter().any(|value| !is_token(value)) {
        return Err(MetadataError::InvalidCollection { field });
    }
    values.sort_unstable();
    values.dedup();
    Ok(values)
}

fn validate_text(field: &'static str, value: &str, maximum: usize) -> Result<(), MetadataError> {
    let valid = !value.is_empty()
        && value.len() <= maximum
        && value.trim() == value
        && !value.chars().any(char::is_control);
    if valid {
        Ok(())
    } else {
        Err(MetadataError::InvalidText { field })
    }
}

fn validate_ascii_text(
    field: &'static str,
    value: &str,
    maximum: usize,
) -> Result<(), MetadataError> {
    validate_text(field, value, maximum)?;
    if value.is_ascii() && !value.bytes().any(|byte| byte.is_ascii_whitespace()) {
        Ok(())
    } else {
        Err(MetadataError::InvalidText { field })
    }
}

fn is_token(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        })
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireContextRef<'a> {
    version: u8,
    state: WireState,
    service_id: &'a str,
    audiences: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    principal: Option<WirePrincipalRef<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    decision_id: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    policy_revision: Option<&'a str>,
}

impl<'a> From<&'a AuthContextV1> for WireContextRef<'a> {
    fn from(context: &'a AuthContextV1) -> Self {
        Self {
            version: AUTH_CONTEXT_VERSION,
            state: context.state.into(),
            service_id: &context.service_id,
            audiences: &context.audiences,
            principal: context.principal.as_ref().map(Into::into),
            decision_id: context.decision_id.as_deref(),
            policy_revision: context.policy_revision.as_deref(),
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum WireState {
    Anonymous,
    Authenticated,
}

impl From<AuthStateV1> for WireState {
    fn from(value: AuthStateV1) -> Self {
        match value {
            AuthStateV1::Anonymous => Self::Anonymous,
            AuthStateV1::Authenticated => Self::Authenticated,
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WirePrincipalRef<'a> {
    issuer: &'a str,
    subject: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    tenant_id: Option<&'a str>,
    #[serde(skip_serializing_if = "slice_is_empty")]
    roles: &'a [String],
    #[serde(skip_serializing_if = "slice_is_empty")]
    scopes: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    acr: Option<&'a str>,
    #[serde(skip_serializing_if = "slice_is_empty")]
    amr: &'a [String],
    #[serde(skip_serializing_if = "Option::is_none")]
    actor: Option<WireActorRef<'a>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    auth_time: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    expires_at: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    session_id: Option<&'a str>,
}

impl<'a> From<&'a PrincipalV1> for WirePrincipalRef<'a> {
    fn from(principal: &'a PrincipalV1) -> Self {
        Self {
            issuer: &principal.issuer,
            subject: &principal.subject,
            tenant_id: principal.tenant_id.as_deref(),
            roles: &principal.roles,
            scopes: &principal.scopes,
            acr: principal.acr.as_deref(),
            amr: &principal.amr,
            actor: principal.actor.as_ref().map(Into::into),
            auth_time: principal.auth_time,
            expires_at: principal.expires_at,
            session_id: principal.session_id.as_deref(),
        }
    }
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct WireActorRef<'a> {
    issuer: &'a str,
    subject: &'a str,
}

impl<'a> From<&'a ActorV1> for WireActorRef<'a> {
    fn from(actor: &'a ActorV1) -> Self {
        Self {
            issuer: &actor.issuer,
            subject: &actor.subject,
        }
    }
}

fn slice_is_empty<T>(value: &[T]) -> bool {
    value.is_empty()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireContextOwned {
    version: u8,
    state: WireState,
    service_id: String,
    audiences: Vec<String>,
    principal: Option<WirePrincipalOwned>,
    decision_id: Option<String>,
    policy_revision: Option<String>,
}

impl TryFrom<WireContextOwned> for AuthContextV1 {
    type Error = MetadataError;

    fn try_from(wire: WireContextOwned) -> Result<Self, Self::Error> {
        if wire.version != AUTH_CONTEXT_VERSION {
            return Err(MetadataError::UnsupportedVersion(wire.version));
        }
        match (
            wire.state,
            wire.principal,
            wire.decision_id,
            wire.policy_revision,
        ) {
            (WireState::Anonymous, None, None, None) => {
                Self::anonymous(wire.service_id, wire.audiences)
            }
            (
                WireState::Authenticated,
                Some(principal),
                Some(decision_id),
                Some(policy_revision),
            ) => Self::authenticated(
                wire.service_id,
                wire.audiences,
                principal.try_into()?,
                decision_id,
                policy_revision,
            ),
            _ => Err(MetadataError::InvalidSchema),
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WirePrincipalOwned {
    issuer: String,
    subject: String,
    tenant_id: Option<String>,
    #[serde(default)]
    roles: Vec<String>,
    #[serde(default)]
    scopes: Vec<String>,
    acr: Option<String>,
    #[serde(default)]
    amr: Vec<String>,
    actor: Option<WireActorOwned>,
    auth_time: Option<u64>,
    expires_at: Option<u64>,
    session_id: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireActorOwned {
    issuer: String,
    subject: String,
}

impl TryFrom<WireActorOwned> for ActorV1 {
    type Error = MetadataError;

    fn try_from(wire: WireActorOwned) -> Result<Self, Self::Error> {
        Self::new(wire.issuer, wire.subject)
    }
}

impl TryFrom<WirePrincipalOwned> for PrincipalV1 {
    type Error = MetadataError;

    fn try_from(wire: WirePrincipalOwned) -> Result<Self, Self::Error> {
        PrincipalV1::new(wire.issuer, wire.subject)?
            .with_tenant_id(wire.tenant_id)?
            .with_roles(wire.roles)?
            .with_scopes(wire.scopes)?
            .with_acr(wire.acr)?
            .with_amr(wire.amr)?
            .with_actor(wire.actor.map(TryInto::try_into).transpose()?)
            .with_times(wire.auth_time, wire.expires_at)?
            .with_session_id(wire.session_id)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture_principal() -> PrincipalV1 {
        PrincipalV1::new("https://issuer.example", "user-1")
            .expect("valid identity")
            .with_tenant_id(Some("tenant-1"))
            .expect("valid tenant")
            .with_roles(["operator", "operator"])
            .expect("valid roles")
            .with_scopes(["write", "read"])
            .expect("valid scopes")
            .with_acr(Some("urn:example:loa:2"))
            .expect("valid ACR")
            .with_amr(["otp", "pwd", "pwd"])
            .expect("valid AMR")
            .with_actor(Some(
                ActorV1::new("https://workload.example", "job-1").expect("valid actor"),
            ))
            .with_times(Some(100), Some(200))
            .expect("valid times")
            .with_session_id(Some("session-1"))
            .expect("valid session")
    }

    #[test]
    fn authenticated_context_round_trips_with_canonical_identity() {
        let context = AuthContextV1::authenticated(
            "orders-api",
            ["api://orders-write", "api://orders"],
            fixture_principal(),
            "decision-1",
            "revision-7",
        )
        .expect("valid context");

        let encoded = encode_auth_context(&context).expect("context encodes");
        let decoded = decode_auth_context(&encoded).expect("context decodes");

        assert_eq!(decoded, context);
        assert_eq!(
            decoded.principal().map(PrincipalV1::identity_key),
            Some(("https://issuer.example", "user-1"))
        );
        assert_eq!(decoded.audiences(), &["api://orders", "api://orders-write"]);
        let principal = decoded.principal().expect("authenticated principal");
        assert_eq!(principal.acr(), Some("urn:example:loa:2"));
        assert_eq!(principal.amr(), &["otp", "pwd"]);
        assert_eq!(
            principal.actor().map(ActorV1::identity_key),
            Some(("https://workload.example", "job-1"))
        );
    }

    #[test]
    fn debug_output_redacts_trusted_identity_and_decision_values() {
        let principal = PrincipalV1::new("issuer-debug-sentinel.example", "subject-debug-sentinel")
            .expect("valid identity")
            .with_actor(Some(
                ActorV1::new(
                    "actor-issuer-debug-sentinel.example",
                    "actor-subject-debug-sentinel",
                )
                .expect("valid actor"),
            ));
        let context = AuthContextV1::authenticated(
            "service-debug-sentinel",
            ["audience-debug-sentinel"],
            principal.clone(),
            "decision-debug-sentinel",
            "policy-debug-sentinel",
        )
        .expect("valid context");
        let encoded = encode_auth_context(&context).expect("context encodes");

        for debug in [
            format!("{:?}", principal.actor().expect("actor")),
            format!("{principal:?}"),
            format!("{context:?}"),
        ] {
            assert!(debug.contains("redacted"));
            assert!(!debug.contains("debug-sentinel"));
        }
        assert!(!format!("{encoded:?}").contains("debug-sentinel"));
        assert!(encoded.is_sensitive());
        assert!(encoded.clone().is_sensitive());
    }

    #[test]
    fn anonymous_context_has_no_identity_or_decision() {
        let context = AuthContextV1::anonymous("public-api", ["public-api"])
            .expect("valid anonymous context");
        let decoded =
            decode_auth_context(&encode_auth_context(&context).expect("encodes")).expect("decodes");

        assert_eq!(decoded.state(), AuthStateV1::Anonymous);
        assert!(decoded.principal().is_none());
        assert!(decoded.decision_id().is_none());
        assert!(decoded.policy_revision().is_none());
    }

    #[test]
    fn service_identity_and_oauth_audience_are_distinct() {
        let context = AuthContextV1::anonymous("orders-api", ["api://orders"])
            .expect("distinct service and audience are valid");
        assert_eq!(context.service_id(), "orders-api");
        assert_eq!(context.audiences(), &["api://orders"]);
    }

    #[test]
    fn context_requires_at_least_one_audience() {
        assert_eq!(
            AuthContextV1::anonymous("orders-api", Vec::<String>::new()),
            Err(MetadataError::InvalidCollection { field: "audiences" })
        );
    }

    #[test]
    fn decoder_rejects_unknown_fields_and_state_mismatch() {
        for json in [
            r#"{"version":1,"state":"anonymous","service_id":"api","audiences":["api"],"unexpected":true}"#,
            r#"{"version":1,"state":"authenticated","service_id":"api","audiences":["api"]}"#,
        ] {
            let value = HeaderValue::from_str(&URL_SAFE_NO_PAD.encode(json)).expect("header");
            assert!(decode_auth_context(&value).is_err(), "{json}");
        }
    }

    #[test]
    fn decoder_rejects_padding_and_oversized_values() {
        assert_eq!(
            decode_auth_context(&HeaderValue::from_static("e30=")),
            Err(MetadataError::InvalidEncoding)
        );
        let value = HeaderValue::from_str(&"a".repeat(MAX_AUTH_CONTEXT_ENCODED_LEN + 1))
            .expect("ASCII header");
        assert_eq!(
            decode_auth_context(&value),
            Err(MetadataError::ContextTooLarge)
        );
    }

    #[test]
    fn parser_rejects_duplicate_context_headers() {
        let context = AuthContextV1::anonymous("api", ["api"]).expect("valid context");
        let value = encode_auth_context(&context).expect("encodes");
        let mut headers = HeaderMap::new();
        headers.append(AUTH_CONTEXT_HEADER, value.clone());
        headers.append(AUTH_CONTEXT_HEADER, value);

        assert_eq!(
            parse_auth_context(&headers),
            Err(MetadataError::DuplicateHeader("auth_context"))
        );
    }

    #[test]
    fn insertion_removes_every_spoofable_reserved_header() {
        let context = AuthContextV1::anonymous("api", ["api"]).expect("valid context");
        let mut headers = HeaderMap::new();
        headers.insert("x-wasi-auth-spoofed", HeaderValue::from_static("yes"));
        headers.insert("x-wasi-auth-subject", HeaderValue::from_static("attacker"));
        headers.insert("x-unrelated", HeaderValue::from_static("kept"));

        insert_auth_context(&mut headers, &context).expect("inserts");

        assert!(headers.contains_key(AUTH_CONTEXT_HEADER));
        assert!(!headers.contains_key("x-wasi-auth-subject"));
        assert!(!headers.contains_key("x-wasi-auth-spoofed"));
        assert!(headers.contains_key("x-unrelated"));
    }
}
