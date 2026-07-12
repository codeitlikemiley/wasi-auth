//! Native trusted-ingress authentication and HTTP security policy.

use std::collections::BTreeSet;
use std::error::Error as StdError;
use std::future::Future;

use http::header::{
    ACCESS_CONTROL_ALLOW_CREDENTIALS, ACCESS_CONTROL_ALLOW_HEADERS, ACCESS_CONTROL_ALLOW_METHODS,
    ACCESS_CONTROL_ALLOW_ORIGIN, ACCESS_CONTROL_REQUEST_HEADERS, ACCESS_CONTROL_REQUEST_METHOD,
    AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_SECURITY_POLICY, COOKIE, ORIGIN,
    REFERRER_POLICY, STRICT_TRANSPORT_SECURITY, VARY, X_CONTENT_TYPE_OPTIONS,
};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use thiserror::Error;

use crate::authentication::Clock;
use crate::context::{
    AuthenticationAssurance, AuthorizationSnapshot, ContextError, DecisionId, OrganizationId,
    PolicyRevision, Principal, RequestId, SessionId, ValidatedContextParts, VerifiedAuthContext,
    VerifiedRequestContext,
};

/// Default bounded body size for auth, REST, and unary gRPC requests.
pub const DEFAULT_MAX_REQUEST_BODY_BYTES: usize = 256 * 1024;
/// Canonical request correlation header.
pub const REQUEST_ID_HEADER: HeaderName = HeaderName::from_static("x-request-id");
/// Internal identity metadata header removed from every public request.
pub const AUTH_CONTEXT_HEADER: HeaderName = HeaderName::from_static("x-wasi-auth-context");
const LEGACY_SESSION_HEADER: HeaderName = HeaderName::from_static("x-auth-session");
const LEGACY_ADMIN_HEADER: HeaderName = HeaderName::from_static("x-auth-admin-token");
/// Browser CSRF header paired with the host-only CSRF cookie.
pub const CSRF_HEADER: HeaderName = HeaderName::from_static("x-csrf-token");

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
    /// Returns `false` without adding headers when the origin is absent or not
    /// allowed.
    pub fn apply<B>(&self, request_headers: &HeaderMap, response: &mut Response<B>) -> bool {
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
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum Credential {
    /// Authorization bearer token.
    Bearer(String),
    /// Host-only browser session cookie.
    SessionCookie(String),
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

/// Removes every externally supplied internal identity header.
pub fn strip_untrusted_auth_metadata(headers: &mut HeaderMap) {
    headers.remove(AUTH_CONTEXT_HEADER);
    headers.remove(LEGACY_SESSION_HEADER);
    headers.remove(LEGACY_ADMIN_HEADER);
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
pub fn apply_response_security<B>(
    response: &mut Response<B>,
    policy: ResponseSecurityPolicy,
    secure_transport: bool,
) {
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
    headers.insert(X_CONTENT_TYPE_OPTIONS, HeaderValue::from_static("nosniff"));
    headers.insert(REFERRER_POLICY, HeaderValue::from_static("same-origin"));
    if policy != ResponseSecurityPolicy::ImmutableAsset {
        headers.insert(
            CONTENT_SECURITY_POLICY,
            HeaderValue::from_static("default-src 'self'; frame-ancestors 'none'; base-uri 'self'"),
        );
    }
    if secure_transport {
        headers.insert(
            STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        );
    } else {
        headers.remove(STRICT_TRANSPORT_SECURITY);
    }
}

fn validate_content_length<E>(headers: &HeaderMap, limit: usize) -> Result<(), HttpBoundaryError<E>>
where
    E: StdError + Send + Sync + 'static,
{
    let values = headers.get_all(CONTENT_LENGTH);
    let mut lengths = values.iter();
    let first = lengths.next();
    if lengths.next().is_some() {
        return Err(HttpBoundaryError::InvalidContentLength);
    }
    if let Some(value) = first {
        let length = value
            .to_str()
            .ok()
            .and_then(|text| text.parse::<usize>().ok())
            .ok_or(HttpBoundaryError::InvalidContentLength)?;
        if length > limit {
            return Err(HttpBoundaryError::BodyTooLarge);
        }
    }
    Ok(())
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
    let host_session_cookie = cookie_value(headers, "__Host-session")?;
    let development_session_cookie = if allow_development_session_cookie {
        cookie_value(headers, "wasi_auth_dev_session")?
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
}
