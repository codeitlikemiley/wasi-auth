//! Final-WASIp3 AuthZEN HTTP service backed by SpiceDB.
//!
//! This component is a separately deployable policy decision point. Its
//! inbound PEP credential and outbound SpiceDB credential are distinct trust
//! boundaries and cannot be configured with the same bearer token.

#![deny(rustdoc::broken_intra_doc_links)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;
use std::time::Duration;

use bytes::Bytes;
use http::header::{
    ALLOW, AUTHORIZATION, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE, RETRY_AFTER,
    WWW_AUTHENTICATE,
};
use http::{HeaderMap, HeaderValue, Method, Request as HttpRequest, Response as HttpResponse};
use http::{StatusCode, Uri};
use http_body_util::Full;
use wasi_authz_client::wasip3::Wasip3Transport;
use wasi_authz_client::{BearerAuthTransport, BearerToken, DecisionProvider};
use wasi_authz_contract::{
    ACCESS_EVALUATION_PATH, AccessEvaluation, DecisionResponseV1, MAX_DOCUMENT_BYTES,
};
use wasi_authz_spicedb::{PermissionMap, SpiceDbEndpoint, SpiceDbProvider};
use wasip3::http::types::{ErrorCode, Request, Response};

const PEP_BEARER_ENV: &str = "WASI_AUTHZ_PDP_BEARER_TOKEN";
const ALLOW_UNAUTHENTICATED_LOOPBACK_ENV: &str =
    "WASI_AUTHZ_PDP_ALLOW_UNAUTHENTICATED_LOOPBACK_DEV";
const SPICEDB_ENDPOINT_ENV: &str = "WASI_AUTHZ_SPICEDB_ENDPOINT";
const SPICEDB_BEARER_ENV: &str = "WASI_AUTHZ_SPICEDB_BEARER_TOKEN";
const ALLOW_SPICEDB_LOOPBACK_ENV: &str = "WASI_AUTHZ_SPICEDB_ALLOW_LOOPBACK_DEV";
const PERMISSION_MAP_ENV: &str = "WASI_AUTHZ_SPICEDB_ACTION_PERMISSION_MAP";
const POLICY_REVISION_ENV: &str = "WASI_AUTHZ_SPICEDB_POLICY_REVISION";
const MODEL_VERSION_ENV: &str = "WASI_AUTHZ_SPICEDB_MODEL_VERSION";
const SPICEDB_DEADLINE: Duration = Duration::from_secs(2);
const MAX_PERMISSION_MAPPINGS: usize = 64;
const MAX_PERMISSION_MAP_BYTES: usize = 8 * 1024;
static DIAGNOSTICS_ENABLED: OnceLock<bool> = OnceLock::new();

fn diagnostic_stage(stage: &'static str) {
    let enabled = DIAGNOSTICS_ENABLED.get_or_init(diagnostics_enabled_from_environment);
    if *enabled {
        eprintln!("wasi.middleware stage={stage}");
    }
}

#[cfg(target_arch = "wasm32")]
fn diagnostics_enabled_from_environment() -> bool {
    wasip3::cli::environment::get_environment()
        .iter()
        .any(|(name, value)| name == "WASI_MIDDLEWARE_DIAGNOSTICS" && value == "true")
}

#[cfg(not(target_arch = "wasm32"))]
const fn diagnostics_enabled_from_environment() -> bool {
    false
}

type ComponentProvider = SpiceDbProvider<BearerAuthTransport<Wasip3Transport>>;

static CONFIG: OnceLock<Result<ComponentConfig, ConfigError>> = OnceLock::new();

struct ComponentConfig {
    inbound_authentication: PepAuthentication,
    provider: ComponentProvider,
}

impl fmt::Debug for ComponentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentConfig")
            .field("inbound_authentication", &"[REDACTED]")
            .field("provider", &"[REDACTED]")
            .finish()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ConfigError {
    Missing,
    Duplicate,
    Invalid,
    CredentialReuse,
}

enum PepAuthentication {
    Bearer(BearerToken),
    UnauthenticatedLoopbackDevelopment,
}

impl PepAuthentication {
    fn authorizes(&self, request: &HttpRequest<impl Sized>) -> bool {
        match self {
            Self::Bearer(expected) => single_bearer(request.headers())
                .is_some_and(|actual| constant_time_eq(actual, expected.as_bytes())),
            Self::UnauthenticatedLoopbackDevelopment => {
                !request.headers().contains_key(AUTHORIZATION)
                    && is_http_loopback_uri(request.uri())
            }
        }
    }
}

impl ComponentConfig {
    fn from_environment(environment: &[(String, String)]) -> Result<Self, ConfigError> {
        let values = selected_environment(environment)?;
        let spicedb_endpoint_value = required(&values, SPICEDB_ENDPOINT_ENV)?;
        let allow_spicedb_loopback = boolean(&values, ALLOW_SPICEDB_LOOPBACK_ENV)?;
        let spicedb_endpoint = if allow_spicedb_loopback {
            SpiceDbEndpoint::new_loopback_for_dev(spicedb_endpoint_value)
        } else {
            SpiceDbEndpoint::new(spicedb_endpoint_value)
        }
        .map_err(|_| ConfigError::Invalid)?;

        let spicedb_token = required(&values, SPICEDB_BEARER_ENV)?;
        let inbound_authentication = match (
            values.get(PEP_BEARER_ENV).copied(),
            boolean(&values, ALLOW_UNAUTHENTICATED_LOOPBACK_ENV)?,
        ) {
            (Some(token), false) => {
                let inbound = BearerToken::new(token).map_err(|_| ConfigError::Invalid)?;
                if constant_time_eq(inbound.as_bytes(), spicedb_token.as_bytes()) {
                    return Err(ConfigError::CredentialReuse);
                }
                PepAuthentication::Bearer(inbound)
            }
            (None, true) => PepAuthentication::UnauthenticatedLoopbackDevelopment,
            _ => return Err(ConfigError::Invalid),
        };

        let permissions = parse_permission_map(required(&values, PERMISSION_MAP_ENV)?)?;
        let transport = Wasip3Transport::new()
            .with_timeout(SPICEDB_DEADLINE)
            .map_err(|_| ConfigError::Invalid)?;
        let transport =
            BearerAuthTransport::new(transport, spicedb_token).map_err(|_| ConfigError::Invalid)?;
        let provider = SpiceDbProvider::new(
            spicedb_endpoint,
            transport,
            permissions,
            required(&values, POLICY_REVISION_ENV)?,
            required(&values, MODEL_VERSION_ENV)?,
        )
        .map_err(|_| ConfigError::Invalid)?;
        Ok(Self {
            inbound_authentication,
            provider,
        })
    }
}

fn selected_environment(
    environment: &[(String, String)],
) -> Result<BTreeMap<&str, &str>, ConfigError> {
    let mut values = BTreeMap::new();
    for (name, value) in environment {
        if matches!(
            name.as_str(),
            PEP_BEARER_ENV
                | ALLOW_UNAUTHENTICATED_LOOPBACK_ENV
                | SPICEDB_ENDPOINT_ENV
                | SPICEDB_BEARER_ENV
                | ALLOW_SPICEDB_LOOPBACK_ENV
                | PERMISSION_MAP_ENV
                | POLICY_REVISION_ENV
                | MODEL_VERSION_ENV
        ) && values.insert(name.as_str(), value.as_str()).is_some()
        {
            return Err(ConfigError::Duplicate);
        }
    }
    Ok(values)
}

fn required<'a>(
    values: &'a BTreeMap<&str, &str>,
    name: &'static str,
) -> Result<&'a str, ConfigError> {
    values
        .get(name)
        .copied()
        .filter(|value| !value.is_empty())
        .ok_or(ConfigError::Missing)
}

fn boolean(values: &BTreeMap<&str, &str>, name: &'static str) -> Result<bool, ConfigError> {
    match values.get(name).copied() {
        None | Some("false") => Ok(false),
        Some("true") => Ok(true),
        Some(_) => Err(ConfigError::Invalid),
    }
}

fn parse_permission_map(value: &str) -> Result<PermissionMap, ConfigError> {
    if value.is_empty() || value.len() > MAX_PERMISSION_MAP_BYTES {
        return Err(ConfigError::Invalid);
    }
    let mut mappings = Vec::new();
    for entry in value.split(',') {
        if mappings.len() == MAX_PERMISSION_MAPPINGS {
            return Err(ConfigError::Invalid);
        }
        let (action, permission) = entry.split_once('=').ok_or(ConfigError::Invalid)?;
        if action.is_empty()
            || permission.is_empty()
            || action.contains('=')
            || permission.contains('=')
        {
            return Err(ConfigError::Invalid);
        }
        mappings.push((action, permission));
    }
    PermissionMap::new(mappings).map_err(|_| ConfigError::Invalid)
}

struct Component;

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let Ok(config) = CONFIG
            .get_or_init(|| {
                ComponentConfig::from_environment(&wasip3::cli::environment::get_environment())
            })
            .as_ref()
        else {
            diagnostic_stage("spicedb_pdp_config");
            return into_wasi_response(error_response(StatusCode::SERVICE_UNAVAILABLE));
        };
        let request = match wasip3::http_compat::http_from_wasi_request(request) {
            Ok(request) => request,
            Err(_) => {
                diagnostic_stage("spicedb_pdp_request_conversion");
                return into_wasi_response(error_response(StatusCode::SERVICE_UNAVAILABLE));
            }
        };
        let (mut parts, mut body) = request.into_parts();
        let request_without_body = HttpRequest::from_parts(parts.clone(), ());
        if !config
            .inbound_authentication
            .authorizes(&request_without_body)
        {
            diagnostic_stage("spicedb_pdp_inbound_authentication");
            return into_wasi_response(error_response(StatusCode::UNAUTHORIZED));
        }
        parts.headers.remove(AUTHORIZATION);
        if parts.method != Method::POST {
            return into_wasi_response(response(
                StatusCode::METHOD_NOT_ALLOWED,
                Vec::new(),
                [(ALLOW, HeaderValue::from_static("POST"))],
            ));
        }
        if parts.uri.path() != ACCESS_EVALUATION_PATH || parts.uri.query().is_some() {
            return into_wasi_response(error_response(StatusCode::NOT_FOUND));
        }
        if !has_single_json_content_type(&parts.headers) {
            return into_wasi_response(error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE));
        }
        let declared_length = match declared_content_length(&parts.headers) {
            Ok(length) => length,
            Err(status) => {
                if status.is_server_error() {
                    diagnostic_stage("spicedb_pdp_content_length");
                }
                return into_wasi_response(error_response(status));
            }
        };
        let body = match collect_bounded_body(&mut body, declared_length).await {
            Ok(body) => body,
            Err(status) => {
                if status.is_server_error() {
                    diagnostic_stage("spicedb_pdp_body");
                }
                return into_wasi_response(error_response(status));
            }
        };
        let request = HttpRequest::from_parts(parts, body);
        let response = handle_authzen_request(&config.provider, request).await;
        into_wasi_response(response)
    }
}

async fn collect_bounded_body<B>(
    body: &mut B,
    declared_length: usize,
) -> Result<Vec<u8>, StatusCode>
where
    B: http_body_util::BodyExt<Data = Bytes, Error = ErrorCode> + Unpin,
{
    let mut collected = Vec::with_capacity(declared_length);
    while let Some(frame) = body.frame().await {
        let frame = frame.map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
        match frame.into_data() {
            Ok(data) => {
                if collected.len().saturating_add(data.len()) > MAX_DOCUMENT_BYTES {
                    return Err(StatusCode::PAYLOAD_TOO_LARGE);
                }
                collected.extend_from_slice(&data);
            }
            Err(frame) => match frame.into_trailers() {
                Ok(trailers) => drop(trailers),
                Err(_) => return Err(StatusCode::BAD_REQUEST),
            },
        }
    }
    if collected.len() != declared_length {
        return Err(StatusCode::BAD_REQUEST);
    }
    Ok(collected)
}

async fn handle_authzen_request<P>(
    provider: &P,
    request: HttpRequest<Vec<u8>>,
) -> HttpResponse<Vec<u8>>
where
    P: DecisionProvider,
{
    if request.method() != Method::POST {
        return response(
            StatusCode::METHOD_NOT_ALLOWED,
            Vec::new(),
            [(ALLOW, HeaderValue::from_static("POST"))],
        );
    }
    if request.uri().path() != ACCESS_EVALUATION_PATH || request.uri().query().is_some() {
        return error_response(StatusCode::NOT_FOUND);
    }
    if !has_single_json_content_type(request.headers()) {
        return error_response(StatusCode::UNSUPPORTED_MEDIA_TYPE);
    }
    let evaluation = match AccessEvaluation::from_json_slice(request.body()) {
        Ok(evaluation) => evaluation,
        Err(_) => return error_response(StatusCode::BAD_REQUEST),
    };
    let decision = match provider.evaluate(&evaluation).await {
        Ok(decision) => decision,
        Err(_) => {
            diagnostic_stage("spicedb_upstream");
            return error_response(StatusCode::SERVICE_UNAVAILABLE);
        }
    };
    decision_response(decision)
}

fn decision_response(decision: DecisionResponseV1) -> HttpResponse<Vec<u8>> {
    let body = match decision.to_json_vec() {
        Ok(body) if body.len() <= MAX_DOCUMENT_BYTES => body,
        _ => return error_response(StatusCode::SERVICE_UNAVAILABLE),
    };
    response(
        StatusCode::OK,
        body,
        [(CONTENT_TYPE, HeaderValue::from_static("application/json"))],
    )
}

fn has_single_json_content_type(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_TYPE).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value.to_str().ok().is_some_and(|value| {
        value
            .split(';')
            .next()
            .is_some_and(|media_type| media_type.trim().eq_ignore_ascii_case("application/json"))
    })
}

fn declared_content_length(headers: &HeaderMap) -> Result<usize, StatusCode> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return Err(StatusCode::BAD_REQUEST);
    };
    if values.next().is_some() {
        return Err(StatusCode::BAD_REQUEST);
    }
    let length = value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or(StatusCode::BAD_REQUEST)?;
    if length > MAX_DOCUMENT_BYTES {
        Err(StatusCode::PAYLOAD_TOO_LARGE)
    } else {
        Ok(length)
    }
}

fn single_bearer(headers: &HeaderMap) -> Option<&[u8]> {
    let mut values = headers.get_all(AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    value.as_bytes().strip_prefix(b"Bearer ")
}

fn is_http_loopback_uri(uri: &Uri) -> bool {
    uri.scheme_str() == Some("http")
        && uri
            .host()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]"))
}

fn constant_time_eq(actual: &[u8], expected: &[u8]) -> bool {
    let mut difference = actual.len() ^ expected.len();
    let maximum = actual.len().max(expected.len());
    for index in 0..maximum {
        let left = actual.get(index).copied().unwrap_or_default();
        let right = expected.get(index).copied().unwrap_or_default();
        difference |= usize::from(left ^ right);
    }
    difference == 0
}

fn error_response(status: StatusCode) -> HttpResponse<Vec<u8>> {
    let mut response = response(status, Vec::new(), []);
    if status == StatusCode::UNAUTHORIZED {
        response
            .headers_mut()
            .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    }
    if status == StatusCode::SERVICE_UNAVAILABLE {
        response
            .headers_mut()
            .insert(RETRY_AFTER, HeaderValue::from_static("1"));
    }
    response
}

fn response<const N: usize>(
    status: StatusCode,
    body: Vec<u8>,
    additional: [(http::HeaderName, HeaderValue); N],
) -> HttpResponse<Vec<u8>> {
    let length = body.len();
    let mut response = HttpResponse::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    for (name, value) in additional {
        response.headers_mut().insert(name, value);
    }
    if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
        response.headers_mut().insert(CONTENT_LENGTH, value);
    }
    response
}

fn into_wasi_response(response: HttpResponse<Vec<u8>>) -> Result<Response, ErrorCode> {
    wasip3::http_compat::http_into_wasi_response(response.map(|body| Full::new(Bytes::from(body))))
}

wasip3::http::service::export!(Component);

#[cfg(test)]
mod tests {
    use super::*;
    use wasi_authz_client::{ProviderFuture, TransportError};
    use wasi_authz_contract::{Action, DecisionMetadataV1, Resource, SubjectV1};

    #[test]
    fn configuration_requires_separate_pep_and_spicedb_credentials() {
        let environment = fixture_environment();
        assert!(ComponentConfig::from_environment(&environment).is_ok());

        let mut reused = environment;
        let spicedb = reused
            .iter()
            .find(|(name, _)| name == SPICEDB_BEARER_ENV)
            .expect("fixture contains SpiceDB token")
            .1
            .clone();
        reused
            .iter_mut()
            .find(|(name, _)| name == PEP_BEARER_ENV)
            .expect("fixture contains PEP token")
            .1 = spicedb;
        assert!(matches!(
            ComponentConfig::from_environment(&reused),
            Err(ConfigError::CredentialReuse)
        ));
    }

    #[test]
    fn component_debug_never_exposes_credentials_or_provider_metadata() {
        let environment = fixture_environment();
        let config = ComponentConfig::from_environment(&environment).expect("valid fixture");
        let debug = format!("{config:?}");

        assert!(!debug.contains("pep-secret"));
        assert!(!debug.contains("spicedb-secret"));
        assert!(!debug.contains("schema-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn unauthenticated_development_is_restricted_to_http_loopback() {
        let authentication = PepAuthentication::UnauthenticatedLoopbackDevelopment;
        assert!(authentication.authorizes(&empty_request("http://127.0.0.1/evaluate")));
        assert!(authentication.authorizes(&empty_request("http://localhost/evaluate")));
        assert!(!authentication.authorizes(&empty_request("https://localhost/evaluate")));
        assert!(!authentication.authorizes(&empty_request("http://pdp.internal/evaluate")));

        let mut request = empty_request("http://127.0.0.1/evaluate");
        request.headers_mut().insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer should-not-be-forwarded"),
        );
        assert!(!authentication.authorizes(&request));
    }

    #[test]
    fn inbound_bearer_is_single_and_exact() {
        let authentication = PepAuthentication::Bearer(
            BearerToken::new("pep-secret-0123456789").expect("valid fixture"),
        );
        let mut request = empty_request("https://pdp.example/evaluate");
        request.headers_mut().insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer pep-secret-0123456789"),
        );
        assert!(authentication.authorizes(&request));
        request.headers_mut().append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer pep-secret-0123456789"),
        );
        assert!(!authentication.authorizes(&request));
    }

    #[test]
    fn permission_map_is_explicit_bounded_and_supports_counter_action() {
        assert!(parse_permission_map("counter.increment=increment").is_ok());
        assert!(parse_permission_map("").is_err());
        assert!(parse_permission_map("counter.increment").is_err());
        assert!(
            parse_permission_map("counter.increment=increment,counter.increment=read").is_err()
        );
        let too_many = (0..=MAX_PERMISSION_MAPPINGS)
            .map(|index| format!("counter.action{index}=permission{index}"))
            .collect::<Vec<_>>()
            .join(",");
        assert!(parse_permission_map(&too_many).is_err());
    }

    #[test]
    fn content_length_is_strict_and_bounded() {
        let mut headers = HeaderMap::new();
        assert_eq!(
            declared_content_length(&headers),
            Err(StatusCode::BAD_REQUEST)
        );
        headers.insert(CONTENT_LENGTH, HeaderValue::from_static("12"));
        assert_eq!(declared_content_length(&headers), Ok(12));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("12"));
        assert_eq!(
            declared_content_length(&headers),
            Err(StatusCode::BAD_REQUEST)
        );
        headers.remove(CONTENT_LENGTH);
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&(MAX_DOCUMENT_BYTES + 1).to_string()).expect("valid header"),
        );
        assert_eq!(
            declared_content_length(&headers),
            Err(StatusCode::PAYLOAD_TOO_LARGE)
        );
    }

    #[test]
    fn authzen_service_returns_decisions_and_fails_closed() {
        let request = valid_authzen_request();
        let allowed = block_on(handle_authzen_request(&AllowProvider, request));
        assert_eq!(allowed.status(), StatusCode::OK);
        let decision = DecisionResponseV1::from_json_slice(allowed.body())
            .expect("response follows bounded AuthZEN contract");
        assert!(decision.is_allowed());

        let unavailable = block_on(handle_authzen_request(
            &UnavailableProvider,
            valid_authzen_request(),
        ));
        assert_eq!(unavailable.status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(unavailable.body().is_empty());
    }

    #[test]
    fn authzen_endpoint_method_and_media_type_are_exact() {
        let mut wrong_method = valid_authzen_request();
        *wrong_method.method_mut() = Method::GET;
        let response = block_on(handle_authzen_request(&AllowProvider, wrong_method));
        assert_eq!(response.status(), StatusCode::METHOD_NOT_ALLOWED);
        assert_eq!(
            response.headers().get(ALLOW),
            Some(&HeaderValue::from_static("POST"))
        );

        let mut wrong_path = valid_authzen_request();
        *wrong_path.uri_mut() = "/other".parse().expect("valid URI");
        assert_eq!(
            block_on(handle_authzen_request(&AllowProvider, wrong_path)).status(),
            StatusCode::NOT_FOUND
        );

        let mut wrong_type = valid_authzen_request();
        wrong_type
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));
        assert_eq!(
            block_on(handle_authzen_request(&AllowProvider, wrong_type)).status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    #[test]
    fn live_counter_vectors_follow_the_bounded_contract() {
        for document in [
            include_bytes!("../../../fixtures/spicedb-pdp/allow.json").as_slice(),
            include_bytes!("../../../fixtures/spicedb-pdp/deny.json").as_slice(),
            include_bytes!("../../../fixtures/spicedb-pdp/deep.json").as_slice(),
        ] {
            let evaluation =
                AccessEvaluation::from_json_slice(document).expect("fixture follows contract");
            assert_eq!(evaluation.action().name().as_str(), "counter.increment");
            assert_eq!(evaluation.resource().resource_type().as_str(), "counter");
            assert!(matches!(
                evaluation.resource().id().as_str(),
                "session-counter" | "deep-counter"
            ));
        }
    }

    fn fixture_environment() -> Vec<(String, String)> {
        vec![
            (
                PEP_BEARER_ENV.to_owned(),
                "pep-secret-0123456789".to_owned(),
            ),
            (
                SPICEDB_ENDPOINT_ENV.to_owned(),
                "https://spicedb.example/v1/permissions/check".to_owned(),
            ),
            (
                SPICEDB_BEARER_ENV.to_owned(),
                "spicedb-secret-0123456789".to_owned(),
            ),
            (
                PERMISSION_MAP_ENV.to_owned(),
                "counter.increment=increment".to_owned(),
            ),
            (POLICY_REVISION_ENV.to_owned(), "schema-secret-1".to_owned()),
            (MODEL_VERSION_ENV.to_owned(), "spicedb-1.54.0".to_owned()),
        ]
    }

    fn empty_request(uri: &str) -> HttpRequest<()> {
        HttpRequest::builder()
            .uri(uri)
            .body(())
            .expect("fixture request builds")
    }

    fn valid_authzen_request() -> HttpRequest<Vec<u8>> {
        let evaluation = AccessEvaluation::new(
            SubjectV1::Anonymous,
            Action::new("counter.increment").expect("valid fixture"),
            Resource::new("counter", "session-counter").expect("valid fixture"),
        );
        let body = evaluation.to_json_vec().expect("fixture encodes");
        HttpRequest::builder()
            .method(Method::POST)
            .uri(ACCESS_EVALUATION_PATH)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .body(body)
            .expect("fixture request builds")
    }

    #[derive(Debug)]
    struct AllowProvider;

    #[derive(Debug)]
    struct UnavailableProvider;

    #[derive(Debug)]
    struct TestProviderError;

    impl fmt::Display for TestProviderError {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("test provider error")
        }
    }

    impl std::error::Error for TestProviderError {}

    impl DecisionProvider for AllowProvider {
        type Error = TestProviderError;

        fn evaluate<'a>(
            &'a self,
            _evaluation: &'a AccessEvaluation,
        ) -> ProviderFuture<'a, Self::Error> {
            Box::pin(async { Ok(DecisionResponseV1::allow(DecisionMetadataV1::new())) })
        }
    }

    impl DecisionProvider for UnavailableProvider {
        type Error = TransportError;

        fn evaluate<'a>(
            &'a self,
            _evaluation: &'a AccessEvaluation,
        ) -> ProviderFuture<'a, Self::Error> {
            Box::pin(async { Err(TransportError::Unavailable) })
        }
    }

    fn block_on<F>(future: F) -> F::Output
    where
        F: std::future::Future,
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
