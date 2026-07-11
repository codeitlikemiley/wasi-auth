//! Transport-neutral OpenID AuthZEN client.
//!
//! The client serializes only the bounded [`wasi_authz_contract`] profile and
//! accepts only an explicit, valid decision. Network credentials are not part
//! of the request contract and must not be added by application callbacks.

#![deny(rustdoc::broken_intra_doc_links)]

use std::fmt;
use std::future::Future;
use std::pin::Pin;
#[cfg(any(feature = "wasip2", feature = "wasip3"))]
use std::time::Duration;

use http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use http::{Request, Response, StatusCode, Uri};
use thiserror::Error;
use wasi_authz_contract::{
    ACCESS_EVALUATION_PATH, AccessEvaluation, ContractError, DecisionResponseV1, MAX_DOCUMENT_BYTES,
};

#[cfg(feature = "wasip2")]
pub mod wasip2;
#[cfg(feature = "wasip3")]
pub mod wasip3;

/// Boxed future returned by authorization HTTP transports.
pub type TransportFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Response<Vec<u8>>, TransportError>> + Send + 'a>>;

/// HTTP transport used by [`AuthzenClient`].
///
/// Implementations must enforce [`MAX_DOCUMENT_BYTES`] while collecting the
/// response body. They must not follow redirects because a redirect could
/// cross the policy decision trust boundary.
pub trait HttpTransport: Send + Sync {
    /// Sends one complete bounded HTTP request.
    fn send<'a>(&'a self, request: Request<Vec<u8>>) -> TransportFuture<'a>;
}

/// Invalid PEP-to-PDP bearer credential configuration.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum BearerAuthConfigError {
    /// The token violated the bounded RFC 6750 `b64token` grammar.
    #[error("PDP bearer token must be a 16..=4096 byte RFC 6750 b64token")]
    InvalidToken,
}

/// HTTP transport decorator that authenticates the PEP to its PDP.
///
/// The bearer token is carried only in the transport header. It never enters
/// [`AccessEvaluation`] JSON and is always redacted from [`fmt::Debug`].
#[derive(Clone)]
pub struct BearerAuthTransport<T> {
    inner: T,
    token: BearerToken,
}

/// Validated RFC 6750 `b64token` credential with redacted formatting.
#[derive(Clone)]
pub struct BearerToken {
    token: Vec<u8>,
    authorization: http::HeaderValue,
}

impl BearerToken {
    /// Validates a bounded bearer token and marks its header representation
    /// sensitive.
    ///
    /// # Errors
    ///
    /// Returns [`BearerAuthConfigError`] for an invalid RFC 6750 token.
    pub fn new(token: impl AsRef<str>) -> Result<Self, BearerAuthConfigError> {
        let token = token.as_ref();
        if !(16..=4_096).contains(&token.len()) || !is_b64token(token.as_bytes()) {
            return Err(BearerAuthConfigError::InvalidToken);
        }
        let mut authorization = http::HeaderValue::from_str(&format!("Bearer {token}"))
            .map_err(|_| BearerAuthConfigError::InvalidToken)?;
        authorization.set_sensitive(true);
        Ok(Self {
            token: token.as_bytes().to_vec(),
            authorization,
        })
    }

    /// Returns the validated token bytes for constant-time server comparison.
    pub fn as_bytes(&self) -> &[u8] {
        &self.token
    }

    fn authorization(&self) -> http::HeaderValue {
        self.authorization.clone()
    }
}

impl fmt::Debug for BearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("BearerToken([REDACTED])")
    }
}

fn is_b64token(token: &[u8]) -> bool {
    let padding_start = token
        .iter()
        .position(|byte| *byte == b'=')
        .unwrap_or(token.len());
    let (value, padding) = token.split_at(padding_start);
    !value.is_empty()
        && value.iter().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~' | b'+' | b'/')
        })
        && padding.iter().all(|byte| *byte == b'=')
}

impl<T> BearerAuthTransport<T> {
    /// Wraps a transport with one bounded sensitive bearer credential.
    ///
    /// # Errors
    ///
    /// Returns [`BearerAuthConfigError`] for invalid token bytes.
    pub fn new(inner: T, token: impl AsRef<str>) -> Result<Self, BearerAuthConfigError> {
        Ok(Self {
            inner,
            token: BearerToken::new(token)?,
        })
    }
}

impl<T> fmt::Debug for BearerAuthTransport<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("BearerAuthTransport")
            .field("inner", &"[REDACTED]")
            .field("authorization", &"Bearer [REDACTED]")
            .finish()
    }
}

impl<T> HttpTransport for BearerAuthTransport<T>
where
    T: HttpTransport,
{
    fn send<'a>(&'a self, mut request: Request<Vec<u8>>) -> TransportFuture<'a> {
        if request.headers().contains_key(AUTHORIZATION) {
            return Box::pin(async { Err(TransportError::Protocol) });
        }
        request
            .headers_mut()
            .insert(AUTHORIZATION, self.token.authorization());
        self.inner.send(request)
    }
}

/// Boxed future returned by policy decision providers.
pub type ProviderFuture<'a, E> =
    Pin<Box<dyn Future<Output = Result<DecisionResponseV1, E>> + Send + 'a>>;

/// A semantic feature explicitly implemented by a decision provider.
///
/// Capability declarations are descriptive, not an authorization decision.
/// PEPs must still fail closed for every provider error or indeterminate
/// response.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
#[non_exhaustive]
pub enum ProviderCapability {
    /// Accepts the bounded AuthZEN 1.0 access-evaluation contract.
    BoundedAuthzenV1,
    /// Handles the contract's explicit anonymous subject state.
    AnonymousSubjects,
    /// Evaluates typed subject, action, resource, or context attributes.
    TypedAttributes,
    /// Preserves and evaluates trusted attribute provenance.
    AttributeProvenance,
    /// Evaluates provider-native relationship or parent hierarchies.
    RelationshipHierarchy,
    /// Supports minimize-latency consistency requests.
    MinimizeLatencyConsistency,
    /// Supports at-least-as-fresh consistency tokens.
    AtLeastAsFreshConsistency,
    /// Supports fully-consistent evaluation requests.
    FullyConsistentConsistency,
}

/// Shared interface implemented by remote and embedded decision providers.
pub trait DecisionProvider: Send + Sync {
    /// Provider-specific typed error.
    type Error: std::error::Error + Send + Sync + 'static;

    /// Declares provider semantics that have executable conformance coverage.
    ///
    /// The default is deliberately empty so capabilities are never inferred
    /// from a provider merely accepting a request.
    fn capabilities(&self) -> &'static [ProviderCapability] {
        &[]
    }

    /// Evaluates one bounded authorization request.
    fn evaluate<'a>(&'a self, evaluation: &'a AccessEvaluation) -> ProviderFuture<'a, Self::Error>;
}

/// Transport-level failure without raw host error strings.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TransportError {
    /// The transport is unavailable on the current compilation target.
    #[error("authorization transport is unavailable on this target")]
    UnsupportedTarget,
    /// The host rejected an invalid request or response representation.
    #[error("authorization transport protocol failure")]
    Protocol,
    /// The network or composed component could not be reached.
    #[error("authorization provider is unavailable")]
    Unavailable,
    /// The response body exceeded the bounded contract limit.
    #[error("authorization response body exceeds its limit")]
    ResponseTooLarge,
    /// The provider request exceeded its configured deadline.
    #[error("authorization provider request timed out")]
    Timeout,
    /// The owning async task canceled the provider request.
    #[error("authorization provider request was canceled")]
    Canceled,
}

/// Invalid transport timeout policy.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum TransportConfigError {
    /// The deadline was zero, too small, too large, or could not fit WASI nanoseconds.
    #[error("authorization transport timeout must be between 1ms and 60s")]
    InvalidTimeout,
}

#[cfg(any(feature = "wasip2", feature = "wasip3"))]
const DEFAULT_TIMEOUT_NANOS: u64 = 2_000_000_000;
#[cfg(any(feature = "wasip2", feature = "wasip3"))]
const MIN_TIMEOUT: Duration = Duration::from_millis(1);
#[cfg(any(feature = "wasip2", feature = "wasip3"))]
const MAX_TIMEOUT: Duration = Duration::from_secs(60);

#[cfg(any(feature = "wasip2", feature = "wasip3"))]
fn timeout_nanos(timeout: Duration) -> Result<u64, TransportConfigError> {
    if !(MIN_TIMEOUT..=MAX_TIMEOUT).contains(&timeout) {
        return Err(TransportConfigError::InvalidTimeout);
    }
    timeout
        .as_nanos()
        .try_into()
        .map_err(|_| TransportConfigError::InvalidTimeout)
}

/// Validated policy decision endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthzenEndpoint(Uri);

impl AuthzenEndpoint {
    /// Validates a production AuthZEN single-evaluation endpoint.
    ///
    /// Remote endpoints require HTTPS. An internal Spin component endpoint
    /// ending in `.spin.internal` may use HTTP because it is connected by the
    /// runtime rather than an external network.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] for malformed, credential-bearing, queried,
    /// fragmented, or non-HTTP(S) endpoints.
    pub fn new(value: impl AsRef<str>) -> Result<Self, EndpointError> {
        let uri = value
            .as_ref()
            .parse::<Uri>()
            .map_err(|_| EndpointError::Invalid)?;
        let scheme = uri.scheme_str();
        let host = uri.host();
        let secure_transport = scheme == Some("https")
            || (scheme == Some("http")
                && host.is_some_and(|host| host.ends_with(".spin.internal")));
        let valid_authority = uri
            .authority()
            .is_some_and(|authority| !authority.as_str().contains('@'));
        let valid_path = uri.path() == ACCESS_EVALUATION_PATH && uri.query().is_none();
        if !secure_transport || !valid_authority || !valid_path {
            return Err(EndpointError::Invalid);
        }
        Ok(Self(uri))
    }

    /// Validates an HTTP loopback endpoint for explicit local development.
    ///
    /// This constructor must not be used for deployed or remote traffic.
    ///
    /// # Errors
    ///
    /// Returns [`EndpointError`] unless the endpoint uses HTTP and a loopback
    /// host with the exact single-evaluation path.
    pub fn new_loopback_for_dev(value: impl AsRef<str>) -> Result<Self, EndpointError> {
        let uri = value
            .as_ref()
            .parse::<Uri>()
            .map_err(|_| EndpointError::Invalid)?;
        let loopback = uri
            .host()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]"));
        let valid = uri.scheme_str() == Some("http")
            && loopback
            && uri
                .authority()
                .is_some_and(|authority| !authority.as_str().contains('@'))
            && uri.path() == ACCESS_EVALUATION_PATH
            && uri.query().is_none();
        if !valid {
            return Err(EndpointError::Invalid);
        }
        Ok(Self(uri))
    }

    /// Returns the validated endpoint URI.
    pub fn as_uri(&self) -> &Uri {
        &self.0
    }
}

/// Endpoint validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum EndpointError {
    /// The endpoint did not satisfy the absolute bounded endpoint profile.
    #[error("invalid AuthZEN evaluation endpoint")]
    Invalid,
}

/// Client-side evaluation failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ClientError {
    /// The bounded contract could not be encoded or decoded.
    #[error("invalid bounded authorization document")]
    Contract(#[source] ContractError),
    /// The configured transport failed.
    #[error("authorization transport failed")]
    Transport(#[source] TransportError),
    /// The PEP did not authenticate successfully to the PDP.
    #[error("authorization provider rejected PEP authentication")]
    PepAuthentication,
    /// The provider rejected the request shape or method.
    #[error("authorization provider rejected the evaluation request")]
    RejectedRequest,
    /// The provider was unavailable or returned a server error.
    #[error("authorization provider is unavailable")]
    ProviderUnavailable,
    /// The response status, headers, or content type violated the profile.
    #[error("authorization provider returned an invalid response")]
    InvalidResponse,
}

/// Transport-neutral bounded AuthZEN client.
#[derive(Clone, Debug)]
pub struct AuthzenClient<T> {
    endpoint: AuthzenEndpoint,
    transport: T,
}

impl<T> AuthzenClient<T>
where
    T: HttpTransport,
{
    /// Constructs a client from a validated endpoint and transport.
    pub fn new(endpoint: AuthzenEndpoint, transport: T) -> Self {
        Self {
            endpoint,
            transport,
        }
    }

    /// Evaluates one bounded authorization request.
    ///
    /// Domain denials are successful HTTP 200 responses whose decision is
    /// `false`; they are returned as [`DecisionResponseV1`] rather than errors.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError`] for contract, transport, protocol, or provider
    /// failures. Callers must fail closed for every error.
    pub async fn evaluate(
        &self,
        evaluation: &AccessEvaluation,
    ) -> Result<DecisionResponseV1, ClientError> {
        let body = evaluation.to_json_vec().map_err(ClientError::Contract)?;
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(self.endpoint.as_uri().clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .body(body)
            .map_err(|_| ClientError::InvalidResponse)?;
        let response = self
            .transport
            .send(request)
            .await
            .map_err(ClientError::Transport)?;
        decode_response(response)
    }
}

impl<T> DecisionProvider for AuthzenClient<T>
where
    T: HttpTransport,
{
    type Error = ClientError;

    fn capabilities(&self) -> &'static [ProviderCapability] {
        &[ProviderCapability::BoundedAuthzenV1]
    }

    fn evaluate<'a>(&'a self, evaluation: &'a AccessEvaluation) -> ProviderFuture<'a, Self::Error> {
        Box::pin(AuthzenClient::evaluate(self, evaluation))
    }
}

fn decode_response(response: Response<Vec<u8>>) -> Result<DecisionResponseV1, ClientError> {
    match response.status() {
        StatusCode::OK => {}
        StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
            return Err(ClientError::PepAuthentication);
        }
        status if status.is_client_error() => return Err(ClientError::RejectedRequest),
        status if status.is_server_error() => return Err(ClientError::ProviderUnavailable),
        _ => return Err(ClientError::InvalidResponse),
    }
    if response.body().len() > MAX_DOCUMENT_BYTES {
        return Err(ClientError::Transport(TransportError::ResponseTooLarge));
    }
    let content_type = response
        .headers()
        .get(CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .ok_or(ClientError::InvalidResponse)?;
    if !is_json_content_type(content_type) {
        return Err(ClientError::InvalidResponse);
    }
    DecisionResponseV1::from_json_slice(response.body()).map_err(ClientError::Contract)
}

fn is_json_content_type(value: &str) -> bool {
    value
        .split(';')
        .next()
        .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
}

/// Compatibility spelling for [`AuthzenClient`].
pub type AuthZenClient<T> = AuthzenClient<T>;
/// Compatibility spelling for [`AuthzenEndpoint`].
pub type AuthZenEndpoint = AuthzenEndpoint;

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;
    use wasi_authz_contract::{Action, Resource, SubjectV1};

    #[derive(Debug)]
    struct MockTransport {
        response: Mutex<Option<Response<Vec<u8>>>>,
    }

    impl MockTransport {
        fn new(response: Response<Vec<u8>>) -> Self {
            Self {
                response: Mutex::new(Some(response)),
            }
        }
    }

    impl HttpTransport for MockTransport {
        fn send<'a>(&'a self, _request: Request<Vec<u8>>) -> TransportFuture<'a> {
            Box::pin(async move {
                self.response
                    .lock()
                    .map_err(|_| TransportError::Unavailable)?
                    .take()
                    .ok_or(TransportError::Unavailable)
            })
        }
    }

    #[test]
    fn endpoint_rejects_queries_and_credentials() {
        assert!(AuthzenEndpoint::new("https://pdp.example/access/v1/evaluation?debug=1").is_err());
        assert!(AuthzenEndpoint::new("https://user@pdp.example/access/v1/evaluation").is_err());
        assert!(AuthzenEndpoint::new("http://pdp.example/access/v1/evaluation").is_err());
    }

    #[test]
    fn client_accepts_an_explicit_allow() {
        let request = fixture_request("document.read");
        let decision = DecisionResponseV1::allow(wasi_authz_contract::DecisionMetadataV1::new());
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json; charset=utf-8")
            .body(decision.to_json_vec().expect("decision encodes"))
            .expect("response builds");
        let client = AuthzenClient::new(
            AuthzenEndpoint::new("https://pdp.example/access/v1/evaluation")
                .expect("endpoint is valid"),
            MockTransport::new(response),
        );

        let received = block_on(client.evaluate(&request)).expect("decision is valid");

        assert!(received.is_allowed());
    }

    #[test]
    fn domain_deny_is_not_an_http_error() {
        let response = Response::builder()
            .status(StatusCode::OK)
            .header(CONTENT_TYPE, "application/json")
            .body(br#"{"decision":false}"#.to_vec())
            .expect("response builds");
        let client = AuthzenClient::new(
            AuthzenEndpoint::new("https://pdp.example/access/v1/evaluation")
                .expect("endpoint is valid"),
            MockTransport::new(response),
        );
        let request = fixture_request("document.delete");

        let decision = block_on(client.evaluate(&request)).expect("deny is a valid decision");

        assert!(!decision.is_allowed());
    }

    #[test]
    fn bearer_transport_injects_once_and_redacts_debug() {
        let transport =
            BearerAuthTransport::new(CapturingTransport::default(), "transport-secret-token")
                .expect("valid fixture token");
        let request = Request::builder()
            .uri("https://pdp.example/access/v1/evaluation")
            .body(Vec::new())
            .expect("request builds");

        block_on(transport.send(request)).expect("transport sends");

        let requests = transport
            .inner
            .requests
            .lock()
            .expect("fixture mutex is healthy");
        assert_eq!(requests.len(), 1);
        assert_eq!(
            requests[0].headers().get(AUTHORIZATION),
            Some(&http::HeaderValue::from_static(
                "Bearer transport-secret-token"
            ))
        );
        let debug = format!("{transport:?}");
        assert!(!debug.contains("transport-secret-token"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn bearer_transport_rejects_preexisting_authorization() {
        let transport =
            BearerAuthTransport::new(CapturingTransport::default(), "transport-secret-token")
                .expect("valid fixture token");
        let request = Request::builder()
            .uri("https://pdp.example/access/v1/evaluation")
            .header(AUTHORIZATION, "Bearer application-supplied")
            .body(Vec::new())
            .expect("request builds");

        let result = block_on(transport.send(request));

        assert!(matches!(result, Err(TransportError::Protocol)));
        assert!(
            transport
                .inner
                .requests
                .lock()
                .expect("fixture mutex is healthy")
                .is_empty()
        );
    }

    #[test]
    fn bearer_token_rejects_quotes_and_interior_padding() {
        assert!(BearerToken::new("0123456789abcde\"").is_err());
        assert!(BearerToken::new("01234567=89abcdef").is_err());
        assert!(BearerToken::new("0123456789abcdef==").is_ok());
        let token = BearerToken::new("debug-secret-token").expect("valid fixture");
        assert!(!format!("{token:?}").contains("debug-secret-token"));
    }

    #[derive(Debug, Default)]
    struct CapturingTransport {
        requests: Mutex<Vec<Request<Vec<u8>>>>,
    }

    impl HttpTransport for CapturingTransport {
        fn send<'a>(&'a self, request: Request<Vec<u8>>) -> TransportFuture<'a> {
            Box::pin(async move {
                self.requests
                    .lock()
                    .map_err(|_| TransportError::Unavailable)?
                    .push(request);
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(br#"{"decision":true}"#.to_vec())
                    .map_err(|_| TransportError::Protocol)
            })
        }
    }

    fn fixture_request(action: &str) -> AccessEvaluation {
        AccessEvaluation::new(
            SubjectV1::Anonymous,
            Action::new(action).expect("valid fixture"),
            Resource::new("document", "report-1").expect("valid fixture"),
        )
    }

    fn block_on<F>(future: F) -> F::Output
    where
        F: Future,
    {
        use std::task::{Context, Poll, Waker};

        let waker = Waker::noop();
        let mut context = Context::from_waker(waker);
        let mut future = Box::pin(future);
        loop {
            match future.as_mut().poll(&mut context) {
                Poll::Ready(output) => return output,
                Poll::Pending => std::thread::yield_now(),
            }
        }
    }
}
