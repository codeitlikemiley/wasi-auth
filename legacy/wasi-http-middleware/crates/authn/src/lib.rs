//! In-process authentication for terminal WASI HTTP applications.
//!
//! The library sanitizes untrusted wire headers before installing a typed
//! [`VerifiedAuthContext`] in [`http::Extensions`]. It supports either a
//! trusted private ingress or a statically dispatched authentication broker.

#![deny(missing_docs)]

use std::{
    future::Future,
    time::{SystemTime, UNIX_EPOCH},
};

use http::{Request, header::AUTHORIZATION};
use thiserror::Error;
use wasi_http_metadata::{
    AUTH_CONTEXT_HEADER, AuthContextV1, PrincipalV1, REQUEST_ID_HEADER, VerifiedAuthContext,
    parse_auth_context, strip_reserved_auth_headers,
};
use wasi_http_policy_core::{
    AuthDecision, AuthnRequestV1, authorization_value, is_valid_request_id,
};

/// Authentication behavior when a request has no credentials.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthenticationMode {
    /// Reject requests without credentials.
    #[default]
    Required,
    /// Install an explicit anonymous identity without calling the broker.
    Optional,
}

/// Immutable terminal authentication configuration.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationConfig {
    service_id: String,
    audiences: Vec<String>,
    mode: AuthenticationMode,
}

impl AuthenticationConfig {
    /// Creates validated service and audience configuration.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationConfigError`] when the deployment identity is
    /// empty, ambiguous, oversized, or contains an invalid audience.
    pub fn new(
        service_id: impl Into<String>,
        audiences: impl IntoIterator<Item = impl Into<String>>,
        mode: AuthenticationMode,
    ) -> Result<Self, AuthenticationConfigError> {
        let context = AuthContextV1::anonymous(service_id, audiences)
            .map_err(|_| AuthenticationConfigError::InvalidDeploymentIdentity)?;
        Ok(Self {
            service_id: context.service_id().to_owned(),
            audiences: context.audiences().to_vec(),
            mode,
        })
    }

    /// Returns the immutable terminal service identifier.
    #[must_use]
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    /// Returns the accepted authentication audiences.
    #[must_use]
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    /// Returns the missing-credential behavior.
    #[must_use]
    pub fn mode(&self) -> AuthenticationMode {
        self.mode
    }
}

/// Invalid in-process authentication configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum AuthenticationConfigError {
    /// Service or audience configuration violates the metadata contract.
    #[error("invalid authentication deployment identity")]
    InvalidDeploymentIdentity,
}

/// Transport-level broker failure that must not be exposed to clients.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum BrokerTransportError {
    /// The broker could not produce a valid decision.
    #[error("authentication broker unavailable")]
    Unavailable,
}

/// Statically dispatched authentication-broker transport.
pub trait BrokerTransport {
    /// Future returned by [`BrokerTransport::authenticate`].
    type AuthenticateFuture<'a>: Future<Output = Result<AuthDecision, BrokerTransportError>> + 'a
    where
        Self: 'a;

    /// Sends one bounded authentication request to the configured broker.
    fn authenticate<'a>(
        &'a self,
        request: &'a AuthnRequestV1,
        authorization: &'a str,
    ) -> Self::AuthenticateFuture<'a>;
}

/// In-process terminal authentication backed by a broker transport.
#[derive(Clone, Debug)]
pub struct Authenticator<T> {
    config: AuthenticationConfig,
    transport: T,
}

impl<T> Authenticator<T>
where
    T: BrokerTransport,
{
    /// Creates an authenticator with immutable configuration and transport.
    #[must_use]
    pub fn new(config: AuthenticationConfig, transport: T) -> Self {
        Self { config, transport }
    }

    /// Sanitizes and authenticates one terminal request.
    ///
    /// Credentials and all client-supplied trusted metadata are removed before
    /// the broker future is polled. Success installs [`VerifiedAuthContext`]
    /// in the request extensions.
    ///
    /// # Errors
    ///
    /// Returns [`AuthnRejection`] for malformed credentials, missing required
    /// credentials, rejected credentials, or broker failure.
    pub async fn authenticate_request<B>(
        &self,
        request: &mut Request<B>,
    ) -> Result<VerifiedAuthContext, AuthnRejection> {
        let authorization =
            authorization_value(request.headers()).map(|value| value.map(str::to_owned));
        let request_id = canonical_request_id(request).map(str::to_owned);
        sanitize_headers(request);
        let authorization = authorization.map_err(|_| AuthnRejection::InvalidRequest)?;

        let Some(authorization) = authorization else {
            if self.config.mode == AuthenticationMode::Required {
                return Err(AuthnRejection::MissingCredentials);
            }
            let context = AuthContextV1::anonymous(
                self.config.service_id.clone(),
                self.config.audiences.clone(),
            )
            .map_err(|_| AuthnRejection::Unavailable)?;
            return Ok(install_verified(request, context));
        };
        let request_id = request_id.ok_or(AuthnRejection::InvalidRequest)?;
        let broker_request = AuthnRequestV1 {
            version: 1,
            service_id: self.config.service_id.clone(),
            audiences: self.config.audiences.clone(),
            request_id,
        };
        let decision = self
            .transport
            .authenticate(&broker_request, &authorization)
            .await
            .map_err(|_| AuthnRejection::Unavailable)?;
        let context = match decision {
            AuthDecision::Allow(claims) => claims
                .into_context(
                    self.config.service_id.clone(),
                    self.config.audiences.clone(),
                )
                .map_err(|_| AuthnRejection::Unavailable)?,
            AuthDecision::Unauthenticated => return Err(AuthnRejection::InvalidCredentials),
            AuthDecision::Unavailable => return Err(AuthnRejection::Unavailable),
        };
        validate_lifetime(&context, unix_time())?;
        Ok(install_verified(request, context))
    }
}

/// Configuration for accepting authentication from a private trusted ingress.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct TrustedIngressConfig(AuthenticationConfig);

impl TrustedIngressConfig {
    /// Creates a validated trusted-ingress service binding.
    ///
    /// # Errors
    ///
    /// Returns [`AuthenticationConfigError`] for invalid service or audience
    /// configuration.
    pub fn new(
        service_id: impl Into<String>,
        audiences: impl IntoIterator<Item = impl Into<String>>,
    ) -> Result<Self, AuthenticationConfigError> {
        AuthenticationConfig::new(service_id, audiences, AuthenticationMode::Optional).map(Self)
    }
}

/// Accepts and removes one context issued by a private trusted ingress.
///
/// The terminal listener must not be publicly reachable. Any surviving bearer
/// credential makes the boundary invalid. On success, wire metadata is removed
/// and replaced by a typed request extension.
///
/// # Errors
///
/// Returns [`AuthnRejection::InvalidBoundary`] for missing, duplicated,
/// malformed, expired, or incorrectly bound ingress metadata.
pub fn accept_trusted_ingress<B>(
    config: &TrustedIngressConfig,
    request: &mut Request<B>,
) -> Result<VerifiedAuthContext, AuthnRejection> {
    let had_authorization = request.headers().contains_key(AUTHORIZATION);
    let parsed = parse_auth_context(request.headers());
    sanitize_headers(request);
    if had_authorization {
        return Err(AuthnRejection::InvalidBoundary);
    }
    let context = parsed.map_err(|_| AuthnRejection::InvalidBoundary)?;
    if context.service_id() != config.0.service_id
        || !config
            .0
            .audiences
            .iter()
            .any(|expected| context.audiences().iter().any(|actual| actual == expected))
    {
        return Err(AuthnRejection::InvalidBoundary);
    }
    validate_lifetime(&context, unix_time()).map_err(|_| AuthnRejection::InvalidBoundary)?;
    Ok(install_verified(request, context))
}

/// Fail-closed authentication result class.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum AuthnRejection {
    /// Request credentials or correlation metadata were malformed.
    #[error("invalid authentication request")]
    InvalidRequest,
    /// The trusted-ingress boundary was absent or invalid.
    #[error("invalid trusted authentication boundary")]
    InvalidBoundary,
    /// Required credentials were absent.
    #[error("authentication credentials required")]
    MissingCredentials,
    /// Supplied credentials were rejected.
    #[error("authentication credentials rejected")]
    InvalidCredentials,
    /// The broker or trusted metadata contract was unavailable.
    #[error("authentication unavailable")]
    Unavailable,
}

fn canonical_request_id<B>(request: &Request<B>) -> Option<&str> {
    let mut values = request.headers().get_all(&REQUEST_ID_HEADER).iter();
    let value = values.next()?.to_str().ok()?;
    if values.next().is_some() || !is_valid_request_id(value) {
        return None;
    }
    Some(value)
}

fn sanitize_headers<B>(request: &mut Request<B>) {
    request.headers_mut().remove(AUTHORIZATION);
    strip_reserved_auth_headers(request.headers_mut());
    debug_assert!(!request.headers().contains_key(AUTH_CONTEXT_HEADER));
}

fn validate_lifetime(context: &AuthContextV1, now: u64) -> Result<(), AuthnRejection> {
    if context
        .principal()
        .and_then(PrincipalV1::expires_at)
        .is_some_and(|expires_at| expires_at <= now)
    {
        return Err(AuthnRejection::InvalidCredentials);
    }
    Ok(())
}

fn install_verified<B>(request: &mut Request<B>, context: AuthContextV1) -> VerifiedAuthContext {
    let verified = VerifiedAuthContext::new(context);
    request.extensions_mut().insert(verified.clone());
    verified
}

fn unix_time() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_secs())
}

#[cfg(test)]
mod tests {
    use std::{future, pin::Pin};

    use http::{HeaderValue, Request, header::AUTHORIZATION};
    use wasi_http_metadata::{AUTH_CONTEXT_HEADER, AuthContextV1, encode_auth_context};
    use wasi_http_policy_core::{AuthDecision, AuthnRequestV1};

    use super::*;

    #[derive(Clone, Copy, Debug)]
    struct UnavailableTransport;

    impl BrokerTransport for UnavailableTransport {
        type AuthenticateFuture<'a> =
            Pin<Box<dyn Future<Output = Result<AuthDecision, BrokerTransportError>> + 'a>>;

        fn authenticate<'a>(
            &'a self,
            _request: &'a AuthnRequestV1,
            _authorization: &'a str,
        ) -> Self::AuthenticateFuture<'a> {
            Box::pin(future::ready(Err(BrokerTransportError::Unavailable)))
        }
    }

    #[test]
    fn trusted_ingress_should_replace_wire_context_with_extension() {
        let context = AuthContextV1::anonymous("orders", ["api://orders"]).expect("valid context");
        let mut request = Request::new(());
        request.headers_mut().insert(
            AUTH_CONTEXT_HEADER,
            encode_auth_context(&context).expect("encodable context"),
        );
        let config = TrustedIngressConfig::new("orders", ["api://orders"]).expect("valid config");

        let verified = accept_trusted_ingress(&config, &mut request).expect("trusted context");

        assert_eq!(verified.context(), &context);
        assert!(!request.headers().contains_key(AUTH_CONTEXT_HEADER));
        assert!(request.extensions().get::<VerifiedAuthContext>().is_some());
    }

    #[test]
    fn trusted_ingress_should_reject_and_strip_surviving_authorization() {
        let context = AuthContextV1::anonymous("orders", ["api://orders"]).expect("valid context");
        let mut request = Request::new(());
        request.headers_mut().insert(
            AUTH_CONTEXT_HEADER,
            encode_auth_context(&context).expect("encodable context"),
        );
        request
            .headers_mut()
            .insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        let config = TrustedIngressConfig::new("orders", ["api://orders"]).expect("valid config");

        let result = accept_trusted_ingress(&config, &mut request);

        assert_eq!(result, Err(AuthnRejection::InvalidBoundary));
        assert!(!request.headers().contains_key(AUTHORIZATION));
        assert!(!request.headers().contains_key(AUTH_CONTEXT_HEADER));
    }

    #[test]
    fn broker_should_strip_credentials_before_transport_failure_returns() {
        let config =
            AuthenticationConfig::new("orders", ["api://orders"], AuthenticationMode::Required)
                .expect("valid config");
        let authenticator = Authenticator::new(config, UnavailableTransport);
        let mut request = Request::new(());
        request
            .headers_mut()
            .insert(AUTHORIZATION, HeaderValue::from_static("Bearer secret"));
        request
            .headers_mut()
            .insert(REQUEST_ID_HEADER, HeaderValue::from_static("request-1"));

        let result = futures::executor::block_on(authenticator.authenticate_request(&mut request));

        assert_eq!(result, Err(AuthnRejection::Unavailable));
        assert!(!request.headers().contains_key(AUTHORIZATION));
    }
}
