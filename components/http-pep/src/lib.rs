//! Standalone final-WASIp3 coarse HTTP authorization PEP.
//!
//! This component must be composed after trusted authentication middleware and
//! before the terminal service. It is not safe to expose directly to clients.

#![deny(rustdoc::broken_intra_doc_links)]

use std::collections::BTreeMap;
use std::fmt;
use std::sync::OnceLock;
use std::time::Duration;

use http::header::AUTHORIZATION;
use wasi_authz_client::wasip3::Wasip3Transport;
use wasi_authz_client::{
    AuthzenClient, AuthzenEndpoint, BearerAuthTransport, ClientError, DecisionProvider,
    ProviderCapability, ProviderFuture,
};
use wasi_authz_contract::AccessEvaluation;
use wasi_authz_http::coarse_http_evaluation;
use wasi_http_metadata::{AuthContextV1, REQUEST_ID_HEADER, parse_auth_context};
use wasi_http_middleware_component_support::{
    diagnostic_stage, empty_response, request_headers, to_header_map,
};
use wasi_http_policy_core::is_valid_request_id;
use wasip3::http::types::{ErrorCode, Method, Request, Response};

#[allow(missing_docs)]
mod bindings {
    wasi_http_middleware_component_support::generate_middleware_bindings!("../../wit");
}

use bindings::wasi::http::handler;

const SERVICE_ID_ENV: &str = "WASI_AUTHZ_SERVICE_ID";
const ENDPOINT_ENV: &str = "WASI_AUTHZ_ENDPOINT";
const TIMEOUT_MS_ENV: &str = "WASI_AUTHZ_TIMEOUT_MS";
const ALLOW_LOOPBACK_ENV: &str = "WASI_AUTHZ_ALLOW_LOOPBACK_DEV";
const PDP_BEARER_ENV: &str = "WASI_AUTHZ_PDP_BEARER_TOKEN";
const ALLOW_UNAUTHENTICATED_PDP_ENV: &str = "WASI_AUTHZ_ALLOW_UNAUTHENTICATED_PDP_DEV";

static CONFIG: OnceLock<Result<ComponentConfig, ConfigError>> = OnceLock::new();

struct ComponentConfig {
    service_id: String,
    client: ComponentClient,
}

impl fmt::Debug for ComponentConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ComponentConfig")
            .field("service_id", &self.service_id)
            .field("client", &"[REDACTED]")
            .finish()
    }
}

enum ComponentClient {
    Authenticated(AuthzenClient<BearerAuthTransport<Wasip3Transport>>),
    UnauthenticatedDevelopment(AuthzenClient<Wasip3Transport>),
}

impl DecisionProvider for ComponentClient {
    type Error = ClientError;

    fn capabilities(&self) -> &'static [ProviderCapability] {
        &[ProviderCapability::BoundedAuthzenV1]
    }

    fn evaluate<'a>(&'a self, evaluation: &'a AccessEvaluation) -> ProviderFuture<'a, Self::Error> {
        match self {
            Self::Authenticated(client) => Box::pin(client.evaluate(evaluation)),
            Self::UnauthenticatedDevelopment(client) => Box::pin(client.evaluate(evaluation)),
        }
    }
}

#[derive(Clone, Copy, Debug)]
enum ConfigError {
    Missing,
    Duplicate,
    Invalid,
}

struct Component;

bindings::export!(Component with_types_in bindings);

impl bindings::exports::wasi::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let Ok(config) = CONFIG
            .get_or_init(|| {
                ComponentConfig::from_environment(&wasip3::cli::environment::get_environment())
            })
            .as_ref()
        else {
            diagnostic_stage("coarse_pep_config");
            return rejection_response(503);
        };
        let headers = request_headers(&request);
        let Ok(headers) = to_header_map(&headers) else {
            diagnostic_stage("coarse_pep_headers");
            return rejection_response(503);
        };
        let Ok(auth_context) = trusted_auth_context(&headers) else {
            diagnostic_stage("coarse_pep_boundary");
            return rejection_response(503);
        };
        let Ok(request_id) = optional_request_id(&headers) else {
            diagnostic_stage("coarse_pep_request_id");
            return rejection_response(503);
        };
        let method = method_name(&request.get_method());
        let Some(path_with_query) = request.get_path_with_query() else {
            diagnostic_stage("coarse_pep_target");
            return rejection_response(503);
        };
        let Ok(evaluation) = coarse_http_evaluation(
            &auth_context,
            &config.service_id,
            &method,
            &path_with_query,
            request_id.as_deref(),
        ) else {
            diagnostic_stage("coarse_pep_evaluation");
            return rejection_response(503);
        };

        match authorize_then(&config.client, &evaluation, || handler::handle(request)).await {
            GateOutcome::Forwarded(response) => response,
            GateOutcome::Rejected(status) => rejection_response(status),
        }
    }
}

fn trusted_auth_context(headers: &http::HeaderMap) -> Result<AuthContextV1, ()> {
    if headers.contains_key(AUTHORIZATION) {
        return Err(());
    }
    parse_auth_context(headers).map_err(|_| ())
}

enum GateOutcome<T> {
    Forwarded(T),
    Rejected(u16),
}

async fn authorize_then<P, F, Fut, T>(
    provider: &P,
    evaluation: &AccessEvaluation,
    downstream: F,
) -> GateOutcome<T>
where
    P: DecisionProvider,
    F: FnOnce() -> Fut,
    Fut: std::future::Future<Output = T>,
{
    match provider.evaluate(evaluation).await {
        Ok(decision) if decision.is_allowed() => GateOutcome::Forwarded(downstream().await),
        Ok(_) if evaluation.subject().is_authenticated() => GateOutcome::Rejected(403),
        Ok(_) => GateOutcome::Rejected(401),
        Err(_) => {
            diagnostic_stage("coarse_pep_provider");
            GateOutcome::Rejected(503)
        }
    }
}

impl ComponentConfig {
    fn from_environment(environment: &[(String, String)]) -> Result<Self, ConfigError> {
        let mut values = BTreeMap::new();
        for (name, value) in environment {
            if matches!(
                name.as_str(),
                SERVICE_ID_ENV
                    | ENDPOINT_ENV
                    | TIMEOUT_MS_ENV
                    | ALLOW_LOOPBACK_ENV
                    | PDP_BEARER_ENV
                    | ALLOW_UNAUTHENTICATED_PDP_ENV
            ) && values.insert(name.as_str(), value.as_str()).is_some()
            {
                return Err(ConfigError::Duplicate);
            }
        }
        let service_id = values
            .get(SERVICE_ID_ENV)
            .ok_or(ConfigError::Missing)?
            .to_string();
        if service_id.is_empty()
            || service_id.len() > 128
            || !service_id.bytes().all(|byte| {
                byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
            })
        {
            return Err(ConfigError::Invalid);
        }
        let endpoint_value = values.get(ENDPOINT_ENV).ok_or(ConfigError::Missing)?;
        let allow_loopback = match values.get(ALLOW_LOOPBACK_ENV).copied() {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => return Err(ConfigError::Invalid),
        };
        let endpoint = if allow_loopback {
            AuthzenEndpoint::new_loopback_for_dev(endpoint_value)
        } else {
            AuthzenEndpoint::new(endpoint_value)
        }
        .map_err(|_| ConfigError::Invalid)?;
        let timeout_ms = values
            .get(TIMEOUT_MS_ENV)
            .map(|value| value.parse::<u64>().map_err(|_| ConfigError::Invalid))
            .transpose()?
            .unwrap_or(2_000);
        let transport = Wasip3Transport::new()
            .with_timeout(Duration::from_millis(timeout_ms))
            .map_err(|_| ConfigError::Invalid)?;
        let allow_unauthenticated = match values.get(ALLOW_UNAUTHENTICATED_PDP_ENV).copied() {
            None | Some("false") => false,
            Some("true") => true,
            Some(_) => return Err(ConfigError::Invalid),
        };
        let client = match (values.get(PDP_BEARER_ENV).copied(), allow_unauthenticated) {
            (Some(token), false) => ComponentClient::Authenticated(AuthzenClient::new(
                endpoint,
                BearerAuthTransport::new(transport, token).map_err(|_| ConfigError::Invalid)?,
            )),
            (None, true) if allow_loopback => {
                ComponentClient::UnauthenticatedDevelopment(AuthzenClient::new(endpoint, transport))
            }
            _ => return Err(ConfigError::Invalid),
        };
        Ok(Self { service_id, client })
    }
}

fn optional_request_id(headers: &http::HeaderMap) -> Result<Option<String>, ()> {
    let mut values = headers.get_all(&REQUEST_ID_HEADER).iter();
    let Some(value) = values.next() else {
        return Ok(None);
    };
    if values.next().is_some() {
        return Err(());
    }
    let value = value.to_str().map_err(|_| ())?;
    if !is_valid_request_id(value) {
        return Err(());
    }
    Ok(Some(value.to_owned()))
}

fn method_name(method: &Method) -> String {
    match method {
        Method::Get => "GET".to_owned(),
        Method::Head => "HEAD".to_owned(),
        Method::Post => "POST".to_owned(),
        Method::Put => "PUT".to_owned(),
        Method::Delete => "DELETE".to_owned(),
        Method::Connect => "CONNECT".to_owned(),
        Method::Options => "OPTIONS".to_owned(),
        Method::Trace => "TRACE".to_owned(),
        Method::Patch => "PATCH".to_owned(),
        Method::Other(value) => value.to_ascii_uppercase(),
    }
}

fn rejection_response(status: u16) -> Result<Response, ErrorCode> {
    let mut headers = vec![("cache-control".to_owned(), b"no-store".to_vec())];
    if status == 503 {
        headers.push(("retry-after".to_owned(), b"1".to_vec()));
    }
    if status == 401 {
        headers.push(("www-authenticate".to_owned(), b"Bearer".to_vec()));
    }
    empty_response(status, headers)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use wasi_authz_client::ProviderFuture;
    use wasi_authz_contract::{
        Action, DecisionMetadataV1, DecisionResponseV1, Resource, SubjectV1,
    };

    #[test]
    fn configuration_rejects_duplicates() {
        let environment = vec![
            (SERVICE_ID_ENV.to_owned(), "orders-api".to_owned()),
            (SERVICE_ID_ENV.to_owned(), "other-api".to_owned()),
            (
                ENDPOINT_ENV.to_owned(),
                "https://pdp.example/access/v1/evaluation".to_owned(),
            ),
        ];

        assert!(matches!(
            ComponentConfig::from_environment(&environment),
            Err(ConfigError::Duplicate)
        ));
    }

    #[test]
    fn custom_method_is_canonicalized() {
        assert_eq!(
            method_name(&Method::Other("m-search".to_owned())),
            "M-SEARCH"
        );
    }

    #[test]
    fn loopback_requires_explicit_dev_flag() {
        let base = vec![
            (SERVICE_ID_ENV.to_owned(), "orders-api".to_owned()),
            (
                ENDPOINT_ENV.to_owned(),
                "http://127.0.0.1:8080/access/v1/evaluation".to_owned(),
            ),
        ];
        assert!(matches!(
            ComponentConfig::from_environment(&base),
            Err(ConfigError::Invalid)
        ));
        let mut allowed = base;
        allowed.push((ALLOW_LOOPBACK_ENV.to_owned(), "true".to_owned()));
        allowed.push((ALLOW_UNAUTHENTICATED_PDP_ENV.to_owned(), "true".to_owned()));
        assert!(ComponentConfig::from_environment(&allowed).is_ok());
    }

    #[test]
    fn pdp_authentication_is_required_and_redacted() {
        let base = vec![
            (SERVICE_ID_ENV.to_owned(), "orders-api".to_owned()),
            (
                ENDPOINT_ENV.to_owned(),
                "https://pdp.example/access/v1/evaluation".to_owned(),
            ),
        ];
        assert!(matches!(
            ComponentConfig::from_environment(&base),
            Err(ConfigError::Invalid)
        ));
        let mut authenticated = base;
        authenticated.push((
            PDP_BEARER_ENV.to_owned(),
            "component-transport-secret".to_owned(),
        ));

        let config = ComponentConfig::from_environment(&authenticated)
            .expect("valid authenticated configuration");
        let debug = format!("{config:?}");

        assert!(!debug.contains("component-transport-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn unauthenticated_development_rejects_remote_pdp_endpoints() {
        let environment = vec![
            (SERVICE_ID_ENV.to_owned(), "orders-api".to_owned()),
            (
                ENDPOINT_ENV.to_owned(),
                "https://pdp.example/access/v1/evaluation".to_owned(),
            ),
            (ALLOW_UNAUTHENTICATED_PDP_ENV.to_owned(), "true".to_owned()),
        ];

        assert!(matches!(
            ComponentConfig::from_environment(&environment),
            Err(ConfigError::Invalid)
        ));
    }

    #[test]
    fn missing_boundary_or_authorization_header_fails_closed() {
        let mut headers = http::HeaderMap::new();
        assert!(trusted_auth_context(&headers).is_err());
        headers.insert(
            AUTHORIZATION,
            http::HeaderValue::from_static("Bearer untrusted"),
        );
        assert!(trusted_auth_context(&headers).is_err());
    }

    #[test]
    fn request_id_must_match_the_shared_logging_contract() {
        let mut headers = http::HeaderMap::new();
        assert_eq!(optional_request_id(&headers), Ok(None));

        headers.insert(
            &REQUEST_ID_HEADER,
            http::HeaderValue::from_static("request-1"),
        );
        assert_eq!(
            optional_request_id(&headers),
            Ok(Some("request-1".to_owned()))
        );

        headers.insert(
            &REQUEST_ID_HEADER,
            http::HeaderValue::from_static("contains whitespace"),
        );
        assert_eq!(optional_request_id(&headers), Err(()));
    }

    #[test]
    fn downstream_runs_exactly_once_only_for_allow() {
        let calls = AtomicUsize::new(0);
        let evaluation = AccessEvaluation::new(
            SubjectV1::Anonymous,
            Action::new("http.request").expect("valid fixture"),
            Resource::new("service", "orders-api").expect("valid fixture"),
        );

        let outcome = block_on(authorize_then(&AllowProvider, &evaluation, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            204
        }));

        assert!(matches!(outcome, GateOutcome::Forwarded(204)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        let outcome = block_on(authorize_then(&DenyProvider, &evaluation, || async {
            calls.fetch_add(1, Ordering::SeqCst);
            204
        }));
        assert!(matches!(outcome, GateOutcome::Rejected(401)));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[derive(Debug)]
    struct AllowProvider;

    #[derive(Debug)]
    struct DenyProvider;

    #[derive(Debug)]
    struct TestProviderError;

    impl std::fmt::Display for TestProviderError {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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

    impl DecisionProvider for DenyProvider {
        type Error = TestProviderError;

        fn evaluate<'a>(
            &'a self,
            _evaluation: &'a AccessEvaluation,
        ) -> ProviderFuture<'a, Self::Error> {
            Box::pin(async { Ok(DecisionResponseV1::deny(DecisionMetadataV1::new())) })
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
