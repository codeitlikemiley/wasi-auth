//! Fail-closed authentication broker runtime shared by `WASIp3` components.
//!
//! This crate owns configuration validation, broker I/O, deadlines,
//! cancellation-safe in-flight accounting, and conversion to the trusted
//! [`wasi_http_metadata::AuthContextV1`] envelope. Component wrappers remain
//! responsible for stripping credentials and reserved headers before invoking
//! their downstream handler.

#![deny(missing_docs)]

use std::{
    fmt,
    future::IntoFuture,
    net::IpAddr,
    sync::atomic::{AtomicUsize, Ordering},
};

use futures::{
    future::{Either, select},
    pin_mut,
};
use http::{HeaderMap, HeaderValue, StatusCode, Uri};
use thiserror::Error;
use wasi_http_metadata::{AuthContextV1, REQUEST_ID_HEADER, encode_auth_context};
use wasi_http_policy_core::{
    AuthDecision, AuthnRequestV1, authorization_value, parse_authn_response,
};
use wasip3::{
    clocks::monotonic_clock,
    http::{
        client,
        types::{ErrorCode, Headers, Method, Request, RequestOptions, Response, Scheme},
    },
    wit_bindgen::StreamResult,
    wit_future, wit_stream,
};

/// Authentication broker endpoint environment key.
pub const AUTHN_BROKER_URL: &str = "WASI_MIDDLEWARE_AUTHN_BROKER_URL";
/// Authentication deadline environment key, expressed in milliseconds.
pub const AUTHN_TIMEOUT_MS: &str = "WASI_MIDDLEWARE_AUTHN_TIMEOUT_MS";
/// Required or optional authentication mode environment key.
pub const AUTHN_MODE: &str = "WASI_MIDDLEWARE_AUTHN_MODE";
/// Immutable terminal service identifier environment key.
pub const SERVICE_ID: &str = "WASI_MIDDLEWARE_SERVICE_ID";
/// Comma-separated immutable audiences environment key.
pub const AUTHN_AUDIENCES: &str = "WASI_MIDDLEWARE_AUTHN_AUDIENCES";
/// Maximum concurrent broker calls environment key.
pub const AUTHN_MAX_IN_FLIGHT: &str = "WASI_MIDDLEWARE_AUTHN_MAX_IN_FLIGHT";
/// Explicit development-only loopback HTTP opt-in environment key.
pub const AUTHN_ALLOW_INSECURE_LOOPBACK: &str = "WASI_MIDDLEWARE_AUTHN_ALLOW_INSECURE_LOOPBACK";

const DEFAULT_TIMEOUT_MS: u64 = 2_000;
const MAX_TIMEOUT_MS: u64 = 60_000;
const DEFAULT_MAX_IN_FLIGHT: usize = 64;
const MAX_MAX_IN_FLIGHT: usize = 1_024;
const MAX_BROKER_URL_LEN: usize = 2_048;
const MAX_BROKER_RESPONSE_SIZE: usize = 64 * 1024;

static IN_FLIGHT: AtomicUsize = AtomicUsize::new(0);

/// Authentication behavior when no credential is supplied.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthnMode {
    /// Reject requests without credentials.
    #[default]
    Required,
    /// Forward requests without credentials with an anonymous context.
    Optional,
}

/// Fully validated authentication broker configuration.
#[derive(Clone)]
pub struct AuthnConfig {
    scheme: Scheme,
    authority: String,
    path_with_query: String,
    timeout_ns: u64,
    mode: AuthnMode,
    service_id: String,
    audiences: Vec<String>,
    anonymous_context: HeaderValue,
    max_in_flight: usize,
}

impl fmt::Debug for AuthnConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthnConfig")
            .field("mode", &self.mode)
            .field("timeout_ns", &self.timeout_ns)
            .field("max_in_flight", &self.max_in_flight)
            .field("deployment", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl AuthnConfig {
    /// Parses and validates middleware environment configuration.
    ///
    /// Broker URL, service ID, and audiences are required in both modes.
    /// HTTPS is mandatory unless loopback HTTP is explicitly enabled for local
    /// development.
    ///
    /// # Errors
    ///
    /// Returns [`AuthnConfigError`] for missing, duplicate, unsafe, or
    /// out-of-range values.
    pub fn from_environment(environment: &[(String, String)]) -> Result<Self, AuthnConfigError> {
        let allow_insecure_loopback = parse_bool(
            environment_value(environment, AUTHN_ALLOW_INSECURE_LOOPBACK)?,
            false,
        )?;
        let broker_url = environment_value(environment, AUTHN_BROKER_URL)?
            .ok_or(AuthnConfigError::MissingBrokerUrl)?;
        let (scheme, authority, path_with_query) =
            parse_broker_url(broker_url, allow_insecure_loopback)?;

        let timeout_ms = environment_value(environment, AUTHN_TIMEOUT_MS)?
            .map(str::parse::<u64>)
            .transpose()
            .map_err(|_| AuthnConfigError::InvalidTimeout)?
            .unwrap_or(DEFAULT_TIMEOUT_MS);
        if timeout_ms == 0 || timeout_ms > MAX_TIMEOUT_MS {
            return Err(AuthnConfigError::InvalidTimeout);
        }

        let mode = match environment_value(environment, AUTHN_MODE)?.unwrap_or("required") {
            "required" => AuthnMode::Required,
            "optional" => AuthnMode::Optional,
            _ => return Err(AuthnConfigError::InvalidMode),
        };

        let max_in_flight = environment_value(environment, AUTHN_MAX_IN_FLIGHT)?
            .map(str::parse::<usize>)
            .transpose()
            .map_err(|_| AuthnConfigError::InvalidMaxInFlight)?
            .unwrap_or(DEFAULT_MAX_IN_FLIGHT);
        if max_in_flight == 0 || max_in_flight > MAX_MAX_IN_FLIGHT {
            return Err(AuthnConfigError::InvalidMaxInFlight);
        }

        let service_id = environment_value(environment, SERVICE_ID)?
            .ok_or(AuthnConfigError::MissingServiceId)?
            .to_owned();
        let audience_value = environment_value(environment, AUTHN_AUDIENCES)?
            .ok_or(AuthnConfigError::MissingAudiences)?;
        let audiences = audience_value
            .split(',')
            .map(str::trim)
            .map(str::to_owned)
            .collect::<Vec<_>>();
        let deployment = AuthContextV1::anonymous(service_id, audiences)
            .map_err(|_| AuthnConfigError::InvalidDeploymentIdentity)?;
        let anonymous_context = encode_auth_context(&deployment)
            .map_err(|_| AuthnConfigError::InvalidDeploymentIdentity)?;

        Ok(Self {
            scheme,
            authority,
            path_with_query,
            timeout_ns: timeout_ms.saturating_mul(1_000_000),
            mode,
            service_id: deployment.service_id().to_owned(),
            audiences: deployment.audiences().to_vec(),
            anonymous_context,
            max_in_flight,
        })
    }

    /// Returns the configured authentication mode.
    pub fn mode(&self) -> AuthnMode {
        self.mode
    }

    /// Returns the immutable service identifier used as the Bearer realm.
    pub fn service_id(&self) -> &str {
        &self.service_id
    }

    /// Returns immutable configured audiences.
    pub fn audiences(&self) -> &[String] {
        &self.audiences
    }

    /// Returns the bounded concurrent broker-call limit.
    pub fn max_in_flight(&self) -> usize {
        self.max_in_flight
    }
}

/// Authentication configuration failures.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthnConfigError {
    /// The authentication broker URL is absent.
    #[error("missing authentication broker URL")]
    MissingBrokerUrl,
    /// The broker URL is malformed or violates transport policy.
    #[error("invalid authentication broker URL")]
    InvalidBrokerUrl,
    /// The broker deadline is invalid.
    #[error("invalid authentication timeout")]
    InvalidTimeout,
    /// Authentication mode is not `required` or `optional`.
    #[error("invalid authentication mode")]
    InvalidMode,
    /// The terminal service identifier is absent.
    #[error("missing authentication service ID")]
    MissingServiceId,
    /// The audience list is absent.
    #[error("missing authentication audiences")]
    MissingAudiences,
    /// Service or audience configuration violates the V1 metadata contract.
    #[error("invalid authentication deployment identity")]
    InvalidDeploymentIdentity,
    /// The concurrent broker-call limit is invalid.
    #[error("invalid authentication max-in-flight limit")]
    InvalidMaxInFlight,
    /// A boolean environment value is not `true` or `false`.
    #[error("invalid authentication boolean configuration")]
    InvalidBoolean,
    /// An environment key appeared more than once.
    #[error("duplicate middleware environment key")]
    DuplicateEnvironment,
}

/// Result of authenticating one request.
#[derive(Clone, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthnOutcome {
    /// The request may continue with this canonical encoded context header.
    Pass(HeaderValue),
    /// The request must be rejected before downstream invocation.
    Reject(AuthnRejection),
}

impl fmt::Debug for AuthnOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Pass(_) => formatter.write_str("Pass(<redacted-auth-context>)"),
            Self::Reject(rejection) => formatter.debug_tuple("Reject").field(rejection).finish(),
        }
    }
}

/// Fail-closed authentication rejection class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthnRejection {
    /// Authorization or request metadata was malformed.
    InvalidRequest,
    /// Required credentials were absent.
    MissingCredentials,
    /// Supplied credentials were rejected by the broker.
    InvalidCredentials,
    /// The broker was unavailable, malformed, timed out, or saturated.
    Unavailable,
}

/// Safe internal stage classification for an authentication failure.
///
/// The stage is intended for opt-in diagnostics and contains no request data.
/// Client responses continue to use the generic fail-closed status mapping.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum AuthnDiagnosticStage {
    /// Request authorization metadata was malformed.
    InvalidRequest,
    /// Required credentials were not supplied.
    MissingCredentials,
    /// The bounded broker admission guard rejected the request.
    Admission,
    /// The broker transport failed before a valid response was received.
    BrokerTransport,
    /// The broker deadline elapsed.
    BrokerDeadline,
    /// The broker response was malformed or used an unsupported status.
    BrokerProtocol,
    /// A valid broker decision could not be encoded as trusted metadata.
    ContextEncoding,
}

impl AuthnDiagnosticStage {
    /// Returns the stable, secret-free log label for this stage.
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::InvalidRequest => "authn_invalid_request",
            Self::MissingCredentials => "authn_missing_credentials",
            Self::Admission => "authn_admission",
            Self::BrokerTransport => "authn_transport",
            Self::BrokerDeadline => "authn_deadline",
            Self::BrokerProtocol => "authn_protocol",
            Self::ContextEncoding => "authn_context_encoding",
        }
    }
}

impl AuthnRejection {
    /// Returns the HTTP status for this rejection.
    pub fn status(self) -> u16 {
        match self {
            Self::InvalidRequest => 400,
            Self::MissingCredentials | Self::InvalidCredentials => 401,
            Self::Unavailable => 503,
        }
    }

    /// Returns the RFC 6750 challenge for this rejection, when applicable.
    ///
    /// `realm` is safe to quote because [`AuthnConfig`] validates service IDs
    /// against the metadata token grammar.
    pub fn bearer_challenge(self, realm: &str) -> Option<String> {
        match self {
            Self::MissingCredentials => Some(format!("Bearer realm=\"{realm}\"")),
            Self::InvalidCredentials => {
                Some(format!("Bearer realm=\"{realm}\", error=\"invalid_token\""))
            }
            Self::InvalidRequest => Some(format!(
                "Bearer realm=\"{realm}\", error=\"invalid_request\""
            )),
            Self::Unavailable => None,
        }
    }
}

/// Authenticates one request without reading its application body.
///
/// Optional mode skips the broker only when credentials are absent. Supplied
/// credentials are always checked and never downgraded to anonymous access.
/// Dropping this future cancels the active broker future and releases its
/// in-flight slot through an RAII guard.
pub async fn authenticate(
    headers: &HeaderMap,
    request_id: &str,
    config: &AuthnConfig,
) -> AuthnOutcome {
    authenticate_with_diagnostics(headers, request_id, config)
        .await
        .0
}

/// Authenticates one request and returns a safe stage classification for
/// failures.
///
/// The classification is intended for opt-in component diagnostics. It never
/// contains credentials, request paths, query strings, identity values, or
/// provider response bodies. The ordinary [`authenticate`] function remains
/// the compatibility API when callers do not need diagnostics.
pub async fn authenticate_with_diagnostics(
    headers: &HeaderMap,
    request_id: &str,
    config: &AuthnConfig,
) -> (AuthnOutcome, Option<AuthnDiagnosticStage>) {
    let Ok(authorization) = authorization_value(headers) else {
        return (
            AuthnOutcome::Reject(AuthnRejection::InvalidRequest),
            Some(AuthnDiagnosticStage::InvalidRequest),
        );
    };
    let Some(authorization) = authorization else {
        return if config.mode == AuthnMode::Optional {
            (AuthnOutcome::Pass(config.anonymous_context.clone()), None)
        } else {
            (
                AuthnOutcome::Reject(AuthnRejection::MissingCredentials),
                Some(AuthnDiagnosticStage::MissingCredentials),
            )
        };
    };

    let Some(_in_flight) = InFlightGuard::acquire(config.max_in_flight) else {
        return (
            AuthnOutcome::Reject(AuthnRejection::Unavailable),
            Some(AuthnDiagnosticStage::Admission),
        );
    };
    let broker_request = broker_request_for(request_id, config);
    let decision = match call_broker(config, &broker_request, authorization).await {
        Ok(decision) => decision,
        Err(error) => {
            let stage = match error {
                BrokerCallError::Transport => AuthnDiagnosticStage::BrokerTransport,
                BrokerCallError::Deadline => AuthnDiagnosticStage::BrokerDeadline,
                BrokerCallError::Serialization
                | BrokerCallError::InvalidStatus
                | BrokerCallError::ResponseBody => AuthnDiagnosticStage::BrokerProtocol,
            };
            return (
                AuthnOutcome::Reject(AuthnRejection::Unavailable),
                Some(stage),
            );
        }
    };
    match decision {
        AuthDecision::Allow(claims) => match (*claims)
            .into_context(config.service_id.clone(), config.audiences.clone())
            .and_then(|context| encode_auth_context(&context))
        {
            Ok(context) => (AuthnOutcome::Pass(context), None),
            Err(_) => (
                AuthnOutcome::Reject(AuthnRejection::Unavailable),
                Some(AuthnDiagnosticStage::ContextEncoding),
            ),
        },
        AuthDecision::Unauthenticated => (
            AuthnOutcome::Reject(AuthnRejection::InvalidCredentials),
            None,
        ),
        AuthDecision::Unavailable => (
            AuthnOutcome::Reject(AuthnRejection::Unavailable),
            Some(AuthnDiagnosticStage::BrokerProtocol),
        ),
    }
}

#[derive(Clone, Copy, Debug, Error)]
enum BrokerCallError {
    #[error("authentication request serialization failed")]
    Serialization,
    #[error("authentication transport failed")]
    Transport,
    #[error("authentication response status was invalid")]
    InvalidStatus,
    #[error("authentication response body failed")]
    ResponseBody,
    #[error("authentication deadline elapsed")]
    Deadline,
}

struct InFlightGuard;

impl InFlightGuard {
    fn acquire(maximum: usize) -> Option<Self> {
        let mut current = IN_FLIGHT.load(Ordering::Acquire);
        loop {
            if current >= maximum {
                return None;
            }
            match IN_FLIGHT.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Acquire,
            ) {
                Ok(_) => return Some(Self),
                Err(observed) => current = observed,
            }
        }
    }
}

impl Drop for InFlightGuard {
    fn drop(&mut self) {
        IN_FLIGHT.fetch_sub(1, Ordering::AcqRel);
    }
}

fn broker_request_for(request_id: &str, config: &AuthnConfig) -> AuthnRequestV1 {
    AuthnRequestV1 {
        version: 1,
        service_id: config.service_id.clone(),
        audiences: config.audiences.clone(),
        request_id: request_id.to_owned(),
    }
}

async fn call_broker(
    config: &AuthnConfig,
    broker_request: &AuthnRequestV1,
    authorization: &str,
) -> Result<AuthDecision, BrokerCallError> {
    let started = monotonic_clock::now();
    let body = serde_json::to_vec(broker_request).map_err(|_| BrokerCallError::Serialization)?;
    let (status, body) = with_deadline(
        started,
        config.timeout_ns,
        exchange_with_broker(
            config,
            body,
            authorization,
            &broker_request.request_id,
            started,
        ),
    )
    .await??;
    Ok(parse_authn_response(status, &body))
}

async fn exchange_with_broker(
    config: &AuthnConfig,
    body: Vec<u8>,
    authorization: &str,
    request_id: &str,
    started: u64,
) -> Result<(StatusCode, Vec<u8>), BrokerCallError> {
    let fields = vec![
        ("accept".to_owned(), b"application/json".to_vec()),
        ("content-type".to_owned(), b"application/json".to_vec()),
        (
            "content-length".to_owned(),
            body.len().to_string().into_bytes(),
        ),
        (
            REQUEST_ID_HEADER.as_str().to_owned(),
            request_id.as_bytes().to_vec(),
        ),
        (
            "authorization".to_owned(),
            authorization.as_bytes().to_vec(),
        ),
    ];
    let headers = Headers::from_list(&fields).map_err(|_| BrokerCallError::Transport)?;
    let (mut body_writer, body_reader) = wit_stream::new();
    let (body_result_writer, body_result) = wit_future::new(|| Err(ErrorCode::InternalError(None)));
    let options = RequestOptions::new();
    options
        .set_connect_timeout(Some(config.timeout_ns))
        .and_then(|()| options.set_first_byte_timeout(Some(config.timeout_ns)))
        .and_then(|()| options.set_between_bytes_timeout(Some(config.timeout_ns)))
        .map_err(|_| BrokerCallError::Transport)?;
    let (request, transmission_result) =
        Request::new(headers, Some(body_reader), body_result, Some(options));
    request
        .set_method(&Method::Post)
        .and_then(|()| request.set_scheme(Some(&config.scheme)))
        .and_then(|()| request.set_authority(Some(&config.authority)))
        .and_then(|()| request.set_path_with_query(Some(&config.path_with_query)))
        .map_err(|()| BrokerCallError::Transport)?;

    let write_body = async move {
        let remaining = body_writer.write_all(body).await;
        let body_was_written = remaining.is_empty();
        drop(body_writer);
        let result = if body_was_written {
            Ok(None)
        } else {
            Err(ErrorCode::InternalError(None))
        };
        let result_was_published = body_result_writer.write(result).await.is_ok();
        if body_was_written && result_was_published {
            Ok(())
        } else {
            Err(BrokerCallError::Transport)
        }
    };
    let send_and_collect = async move {
        let response = client::send(request)
            .await
            .map_err(|_| BrokerCallError::Transport)?;
        let status = StatusCode::from_u16(response.get_status_code())
            .map_err(|_| BrokerCallError::InvalidStatus)?;
        let body = collect_broker_response(response, started, config.timeout_ns).await?;
        Ok::<_, BrokerCallError>((status, body))
    };
    let await_transmission = async move {
        transmission_result
            .await
            .map_err(|_| BrokerCallError::Transport)
    };
    let (response, (), ()) = futures::try_join!(send_and_collect, write_body, await_transmission)?;
    Ok(response)
}

async fn collect_broker_response(
    response: Response,
    started: u64,
    timeout_ns: u64,
) -> Result<Vec<u8>, BrokerCallError> {
    let (result_writer, body_result) = wit_future::new(|| Err(ErrorCode::InternalError(None)));
    let (mut body, trailers) = Response::consume_body(response, body_result);
    let mut output = Vec::new();
    loop {
        let (status, chunk) =
            with_deadline(started, timeout_ns, body.read(Vec::with_capacity(8 * 1024))).await?;
        if output.len().saturating_add(chunk.len()) > MAX_BROKER_RESPONSE_SIZE {
            return Err(BrokerCallError::ResponseBody);
        }
        output.extend_from_slice(&chunk);
        match status {
            StreamResult::Complete(_) => {}
            StreamResult::Dropped => {
                // Broker trailers do not participate in authentication and are
                // deliberately ignored instead of extending the total deadline.
                drop(trailers);
                result_writer
                    .write(Ok(()))
                    .await
                    .map_err(|_| BrokerCallError::ResponseBody)?;
                return Ok(output);
            }
            StreamResult::Cancelled => return Err(BrokerCallError::ResponseBody),
        }
    }
}

async fn with_deadline<T>(
    started: u64,
    timeout_ns: u64,
    future: impl IntoFuture<Output = T>,
) -> Result<T, BrokerCallError> {
    let elapsed = monotonic_clock::now().saturating_sub(started);
    let remaining = timeout_ns
        .checked_sub(elapsed)
        .filter(|remaining| *remaining > 0)
        .ok_or(BrokerCallError::Deadline)?;
    let future = future.into_future();
    let timer = monotonic_clock::wait_for(remaining);
    pin_mut!(future);
    pin_mut!(timer);
    match select(future, timer).await {
        Either::Left((value, _timer)) => Ok(value),
        Either::Right(((), _future)) => Err(BrokerCallError::Deadline),
    }
}

fn parse_broker_url(
    value: &str,
    allow_insecure_loopback: bool,
) -> Result<(Scheme, String, String), AuthnConfigError> {
    if value.is_empty() || value.len() > MAX_BROKER_URL_LEN {
        return Err(AuthnConfigError::InvalidBrokerUrl);
    }
    let uri = value
        .parse::<Uri>()
        .map_err(|_| AuthnConfigError::InvalidBrokerUrl)?;
    let authority = uri.authority().ok_or(AuthnConfigError::InvalidBrokerUrl)?;
    if authority.as_str().contains('@') {
        return Err(AuthnConfigError::InvalidBrokerUrl);
    }
    let scheme = match uri.scheme_str() {
        Some("https") => Scheme::Https,
        Some("http") if is_spin_internal_host(&uri) => Scheme::Http,
        Some("http") if allow_insecure_loopback && is_loopback_host(&uri) => Scheme::Http,
        _ => return Err(AuthnConfigError::InvalidBrokerUrl),
    };
    let path_with_query = uri
        .path_and_query()
        .map_or("/", http::uri::PathAndQuery::as_str)
        .to_owned();
    Ok((scheme, authority.as_str().to_owned(), path_with_query))
}

fn is_spin_internal_host(uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };
    host.strip_suffix(".spin.internal")
        .is_some_and(|service| !service.is_empty() && !service.contains('.'))
}

fn is_loopback_host(uri: &Uri) -> bool {
    let Some(host) = uri.host() else {
        return false;
    };
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    host.trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .is_ok_and(|address| address.is_loopback())
}

fn parse_bool(value: Option<&str>, default: bool) -> Result<bool, AuthnConfigError> {
    match value {
        None => Ok(default),
        Some("true") => Ok(true),
        Some("false") => Ok(false),
        Some(_) => Err(AuthnConfigError::InvalidBoolean),
    }
}

fn environment_value<'a>(
    environment: &'a [(String, String)],
    key: &str,
) -> Result<Option<&'a str>, AuthnConfigError> {
    let mut values = environment
        .iter()
        .filter(|(name, _)| name == key)
        .map(|(_, value)| value.as_str());
    let value = values.next();
    if values.next().is_some() {
        return Err(AuthnConfigError::DuplicateEnvironment);
    }
    Ok(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn required_environment(url: &str) -> Vec<(String, String)> {
        vec![
            (AUTHN_BROKER_URL.to_owned(), url.to_owned()),
            (SERVICE_ID.to_owned(), "orders-api".to_owned()),
            (
                AUTHN_AUDIENCES.to_owned(),
                "api://orders,api://orders-read".to_owned(),
            ),
        ]
    }

    #[test]
    fn configuration_defaults_are_bounded_and_required() {
        let config = AuthnConfig::from_environment(&required_environment(
            "https://broker.example/authenticate",
        ))
        .expect("valid production configuration");

        assert_eq!(config.mode(), AuthnMode::Required);
        assert_eq!(config.max_in_flight(), DEFAULT_MAX_IN_FLIGHT);
        assert_eq!(config.service_id(), "orders-api");
        assert_eq!(config.audiences(), &["api://orders", "api://orders-read"]);
    }

    #[test]
    fn authentication_debug_output_redacts_configuration_and_context() {
        let config = AuthnConfig::from_environment(&required_environment(
            "https://broker-debug-sentinel.example/authenticate",
        ))
        .expect("valid production configuration");
        let config_debug = format!("{config:?}");
        assert!(config_debug.contains("redacted"));
        assert!(!config_debug.contains("debug-sentinel"));

        let outcome =
            AuthnOutcome::Pass(HeaderValue::from_static("encoded-identity-debug-sentinel"));
        let outcome_debug = format!("{outcome:?}");
        assert!(outcome_debug.contains("redacted"));
        assert!(!outcome_debug.contains("debug-sentinel"));
    }

    #[test]
    fn configuration_rejects_plain_http_by_default() {
        assert_eq!(
            AuthnConfig::from_environment(&required_environment(
                "http://127.0.0.1:19091/authenticate"
            ))
            .expect_err("HTTP must be rejected"),
            AuthnConfigError::InvalidBrokerUrl
        );
    }

    #[test]
    fn explicit_development_mode_allows_only_loopback_http() {
        let mut loopback = required_environment("http://[::1]:19091/authenticate");
        loopback.push((AUTHN_ALLOW_INSECURE_LOOPBACK.to_owned(), "true".to_owned()));
        assert!(AuthnConfig::from_environment(&loopback).is_ok());

        let mut external = required_environment("http://broker.example/authenticate");
        external.push((AUTHN_ALLOW_INSECURE_LOOPBACK.to_owned(), "true".to_owned()));
        assert_eq!(
            AuthnConfig::from_environment(&external).expect_err("external HTTP must fail"),
            AuthnConfigError::InvalidBrokerUrl
        );
    }

    #[test]
    fn spin_internal_http_requires_an_exact_service_suffix() {
        assert!(
            AuthnConfig::from_environment(&required_environment(
                "http://authn.spin.internal/authenticate"
            ))
            .is_ok()
        );

        for url in [
            "http://spin.internal/authenticate",
            "http://evilspin.internal/authenticate",
            "http://authn.spin.internal.evil/authenticate",
            "http://user@authn.spin.internal/authenticate",
        ] {
            assert_eq!(
                AuthnConfig::from_environment(&required_environment(url))
                    .expect_err("ambiguous internal authority must fail"),
                AuthnConfigError::InvalidBrokerUrl,
                "{url}"
            );
        }
    }

    #[test]
    fn broker_payload_contains_no_request_authorization_inputs() {
        let config = AuthnConfig::from_environment(&required_environment(
            "https://broker.example/authenticate",
        ))
        .expect("valid configuration");
        let request = broker_request_for("request-1", &config);
        let json = serde_json::to_string(&request).expect("serializable request");

        assert_eq!(
            json,
            r#"{"version":1,"service_id":"orders-api","audiences":["api://orders","api://orders-read"],"request_id":"request-1"}"#
        );
        for forbidden in [
            "authorization",
            "method",
            "scheme",
            "authority",
            "path",
            "query",
        ] {
            assert!(!json.contains(forbidden), "{forbidden}");
        }
    }

    #[test]
    fn configuration_rejects_an_empty_audience_list() {
        let mut environment = required_environment("https://broker.example/authenticate");
        environment
            .iter_mut()
            .find(|(name, _)| name == AUTHN_AUDIENCES)
            .expect("fixture key")
            .1
            .clear();

        assert_eq!(
            AuthnConfig::from_environment(&environment).expect_err("empty audiences must fail"),
            AuthnConfigError::InvalidDeploymentIdentity
        );
    }

    #[test]
    fn in_flight_guard_releases_capacity_on_drop() {
        assert_eq!(IN_FLIGHT.load(Ordering::Acquire), 0);
        let guard = InFlightGuard::acquire(1).expect("first slot");
        assert!(InFlightGuard::acquire(1).is_none());
        drop(guard);
        assert_eq!(IN_FLIGHT.load(Ordering::Acquire), 0);
        assert!(InFlightGuard::acquire(1).is_some());
    }

    #[test]
    fn bearer_challenges_are_specific_and_safe() {
        assert_eq!(
            AuthnRejection::MissingCredentials.bearer_challenge("orders-api"),
            Some("Bearer realm=\"orders-api\"".to_owned())
        );
        assert_eq!(
            AuthnRejection::InvalidCredentials.bearer_challenge("orders-api"),
            Some("Bearer realm=\"orders-api\", error=\"invalid_token\"".to_owned())
        );
        assert!(
            AuthnRejection::Unavailable
                .bearer_challenge("orders-api")
                .is_none()
        );
    }
}
