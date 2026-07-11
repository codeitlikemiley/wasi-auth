//! Final-WASIp3 AuthZEN HTTP service backed by the reference Cedar policy.
//!
//! The component is intended for internal composition. It fails closed unless
//! a PEP bearer token is configured or unauthenticated internal development is
//! explicitly enabled.

#![deny(rustdoc::broken_intra_doc_links)]

use std::sync::OnceLock;

use bytes::Bytes;
use http::header::{AUTHORIZATION, CONTENT_LENGTH, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderValue, Response as HttpResponse, StatusCode};
use http_body_util::{BodyExt as _, Full};
use wasi_authz_cedar_pdp::CedarPdp;
use wasi_authz_client::BearerToken;
use wasi_authz_contract::MAX_DOCUMENT_BYTES;
use wasip3::http::types::{ErrorCode, Request, Response};

const POLICY: &str = include_str!("../../../fixtures/cedar/http_policy.cedar");
const SCHEMA: &str = include_str!("../../../fixtures/cedar/http_schema.json");
const ENTITIES: &str = include_str!("../../../fixtures/cedar/http_entities.json");

static CONFIG: OnceLock<Result<ComponentConfig, ()>> = OnceLock::new();
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

struct ComponentConfig {
    pdp: CedarPdp,
    authentication: PepAuthentication,
}

impl ComponentConfig {
    fn initialize() -> Result<Self, ()> {
        let environment = wasip3::cli::environment::get_environment();
        let authentication = PepAuthentication::from_environment(&environment)?;
        let pdp =
            CedarPdp::new_validated(POLICY, SCHEMA, ENTITIES, "http-policy-1", "cedar-4.11.2")
                .map_err(|_| ())?;
        Ok(Self {
            pdp,
            authentication,
        })
    }
}

enum PepAuthentication {
    Bearer(BearerToken),
    UnauthenticatedInternalDevelopment,
}

impl PepAuthentication {
    fn from_environment(environment: &[(String, String)]) -> Result<Self, ()> {
        let mut token = None;
        let mut development = None;
        for (name, value) in environment {
            match name.as_str() {
                "WASI_AUTHZ_PDP_BEARER_TOKEN" if token.replace(value.as_str()).is_some() => {
                    return Err(());
                }
                "WASI_AUTHZ_PDP_ALLOW_UNAUTHENTICATED_INTERNAL_DEV"
                    if development.replace(value.as_str()).is_some() =>
                {
                    return Err(());
                }
                _ => {}
            }
        }
        if let Some(token) = token {
            return Ok(Self::Bearer(BearerToken::new(token).map_err(|_| ())?));
        }
        match development {
            Some("true") => Ok(Self::UnauthenticatedInternalDevelopment),
            _ => Err(()),
        }
    }

    fn authorizes(&self, headers: &HeaderMap) -> bool {
        match self {
            Self::UnauthenticatedInternalDevelopment => true,
            Self::Bearer(expected) => {
                let mut values = headers.get_all(AUTHORIZATION).iter();
                let Some(value) = values.next() else {
                    return false;
                };
                if values.next().is_some() {
                    return false;
                }
                value
                    .as_bytes()
                    .strip_prefix(b"Bearer ")
                    .is_some_and(|actual| constant_time_eq(actual, expected.as_bytes()))
            }
        }
    }
}

struct Component;

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let Ok(config) = CONFIG.get_or_init(ComponentConfig::initialize).as_ref() else {
            diagnostic_stage("cedar_pdp_config");
            return into_wasi_response(empty_response(StatusCode::SERVICE_UNAVAILABLE));
        };
        let request = wasip3::http_compat::http_from_wasi_request(request)?;
        let (mut parts, mut body) = request.into_parts();
        if !config.authentication.authorizes(&parts.headers) {
            diagnostic_stage("cedar_pdp_inbound_authentication");
            return into_wasi_response(unauthorized_response());
        }
        parts.headers.remove(AUTHORIZATION);
        if content_length_exceeds_limit(&parts.headers) {
            return into_wasi_response(empty_response(StatusCode::PAYLOAD_TOO_LARGE));
        }
        let mut collected = Vec::new();
        while let Some(frame) = body.frame().await {
            let frame = frame?;
            let Ok(data) = frame.into_data() else {
                return into_wasi_response(empty_response(StatusCode::BAD_REQUEST));
            };
            if collected.len().saturating_add(data.len()) > MAX_DOCUMENT_BYTES {
                return into_wasi_response(empty_response(StatusCode::PAYLOAD_TOO_LARGE));
            }
            collected.extend_from_slice(&data);
        }
        let request = http::Request::from_parts(parts, collected);
        let response = config.pdp.handle(request);
        if response.status().is_server_error() {
            diagnostic_stage("cedar_pdp_provider");
        }
        into_wasi_response(response)
    }
}

fn content_length_exceeds_limit(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return true;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .is_none_or(|length| length > MAX_DOCUMENT_BYTES)
}

fn into_wasi_response(response: HttpResponse<Vec<u8>>) -> Result<Response, ErrorCode> {
    wasip3::http_compat::http_into_wasi_response(response.map(|body| Full::new(Bytes::from(body))))
}

fn empty_response(status: StatusCode) -> HttpResponse<Vec<u8>> {
    let mut response = HttpResponse::new(Vec::new());
    *response.status_mut() = status;
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    response
}

fn unauthorized_response() -> HttpResponse<Vec<u8>> {
    let mut response = empty_response(StatusCode::UNAUTHORIZED);
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
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

wasip3::http::service::export!(Component);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn component_authentication_is_fail_closed_and_duplicate_safe() {
        assert!(PepAuthentication::from_environment(&[]).is_err());
        assert!(
            PepAuthentication::from_environment(&[(
                "WASI_AUTHZ_PDP_ALLOW_UNAUTHENTICATED_INTERNAL_DEV".to_owned(),
                "true".to_owned(),
            )])
            .is_ok()
        );
        let authentication =
            PepAuthentication::Bearer(BearerToken::new("0123456789abcdef").expect("valid fixture"));
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer 0123456789abcdef"),
        );
        assert!(authentication.authorizes(&headers));
        headers.append(
            AUTHORIZATION,
            HeaderValue::from_static("Bearer 0123456789abcdef"),
        );
        assert!(!authentication.authorizes(&headers));
    }
}
