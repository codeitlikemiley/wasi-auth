//! Reference AuthZEN HTTP service backed by a strictly validated Cedar policy.
//!
//! The service core is runtime-neutral. The companion binary provides a
//! bounded loopback-first native HTTP server; a WASI component can reuse the
//! same [`CedarPdp::handle`] contract.

#![deny(rustdoc::broken_intra_doc_links)]

use http::header::{ALLOW, CACHE_CONTROL, CONTENT_LENGTH, CONTENT_TYPE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use wasi_authz_cedar::{CedarError, CedarProvider};
use wasi_authz_contract::{ACCESS_EVALUATION_PATH, AccessEvaluation, MAX_DOCUMENT_BYTES};

/// Strictly activated Cedar policy decision point.
#[derive(Clone, Debug)]
pub struct CedarPdp {
    provider: CedarProvider,
}

impl CedarPdp {
    /// Activates policy, schema, trusted entities, and bounded model metadata
    /// as one immutable snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`CedarError`] when any policy artifact is invalid or strict
    /// validation fails. A partially valid snapshot is never activated.
    pub fn new_validated(
        policy_source: &str,
        schema_source: &str,
        trusted_entities_json: &str,
        policy_revision: impl Into<String>,
        model_version: impl Into<String>,
    ) -> Result<Self, CedarError> {
        Ok(Self {
            provider: CedarProvider::new_validated(
                policy_source,
                schema_source,
                trusted_entities_json,
                policy_revision,
                model_version,
            )?,
        })
    }

    /// Handles one complete bounded AuthZEN HTTP request.
    ///
    /// The caller remains responsible for transport authentication, TLS, and
    /// request deadlines. This method never logs request or decision bodies.
    pub fn handle(&self, request: Request<Vec<u8>>) -> Response<Vec<u8>> {
        if request.method() != Method::POST {
            return empty_response(
                StatusCode::METHOD_NOT_ALLOWED,
                [(ALLOW, HeaderValue::from_static("POST"))],
            );
        }
        if request.uri().path() != ACCESS_EVALUATION_PATH || request.uri().query().is_some() {
            return empty_response(StatusCode::NOT_FOUND, []);
        }
        if !has_single_json_content_type(request.headers()) {
            return empty_response(StatusCode::UNSUPPORTED_MEDIA_TYPE, []);
        }
        if request.body().len() > MAX_DOCUMENT_BYTES {
            return empty_response(StatusCode::PAYLOAD_TOO_LARGE, []);
        }
        if !has_valid_content_length(request.headers(), request.body().len()) {
            return empty_response(StatusCode::BAD_REQUEST, []);
        }
        let evaluation = match AccessEvaluation::from_json_slice(request.body()) {
            Ok(evaluation) => evaluation,
            Err(_) => return empty_response(StatusCode::BAD_REQUEST, []),
        };
        let request_id = evaluation
            .context()
            .and_then(wasi_authz_contract::ContextV1::request_id)
            .map(ToString::to_string);
        let decision = match self.provider.evaluate_sync(&evaluation) {
            Ok(decision) => decision,
            Err(_) => return empty_response(StatusCode::SERVICE_UNAVAILABLE, []),
        };
        let body = match decision.to_json_vec() {
            Ok(body) => body,
            Err(_) => return empty_response(StatusCode::SERVICE_UNAVAILABLE, []),
        };
        let mut response = json_response(StatusCode::OK, body);
        if let Some(request_id) = request_id
            && let Ok(value) = HeaderValue::from_str(&request_id)
        {
            response
                .headers_mut()
                .insert(HeaderName::from_static("x-request-id"), value);
        }
        response
    }
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

fn has_valid_content_length(headers: &HeaderMap, actual: usize) -> bool {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let Some(value) = values.next() else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        == Some(actual)
}

fn json_response(status: StatusCode, body: Vec<u8>) -> Response<Vec<u8>> {
    let length = body.len();
    let mut response = Response::new(body);
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    insert_common_headers(response.headers_mut(), length);
    response
}

fn empty_response<const N: usize>(
    status: StatusCode,
    additional: [(http::HeaderName, HeaderValue); N],
) -> Response<Vec<u8>> {
    let mut response = Response::new(Vec::new());
    *response.status_mut() = status;
    for (name, value) in additional {
        response.headers_mut().insert(name, value);
    }
    insert_common_headers(response.headers_mut(), 0);
    response
}

fn insert_common_headers(headers: &mut HeaderMap, length: usize) {
    headers.insert(CACHE_CONTROL, HeaderValue::from_static("no-store"));
    if let Ok(value) = HeaderValue::from_str(&length.to_string()) {
        headers.insert(CONTENT_LENGTH, value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasi_authz_contract::{AccessEvaluation, Action, Resource, SubjectV1};

    const SCHEMA: &str = r#"{
        "": {
            "entityTypes": {
                "Anonymous": {"shape": {"type": "Record", "attributes": {}}},
                "page": {"shape": {"type": "Record", "attributes": {}}}
            },
            "actions": {
                "page.view": {"appliesTo": {
                    "principalTypes": ["Anonymous"],
                    "resourceTypes": ["page"],
                    "context": {"type": "Record", "attributes": {}}
                }}
            }
        }
    }"#;
    const POLICY: &str =
        r#"permit(principal is Anonymous, action == Action::"page.view", resource is page);"#;

    #[test]
    fn valid_evaluation_returns_an_explicit_json_decision() {
        let pdp = fixture_pdp();
        let evaluation = AccessEvaluation::new(
            SubjectV1::Anonymous,
            Action::new("page.view").expect("valid fixture"),
            Resource::new("page", "home").expect("valid fixture"),
        );
        let body = evaluation.to_json_vec().expect("fixture encodes");
        let request = request(body);

        let response = pdp.handle(request);

        assert_eq!(response.status(), StatusCode::OK);
        let decision = wasi_authz_contract::DecisionResponseV1::from_json_slice(response.body())
            .expect("response follows bounded contract");
        assert!(decision.is_allowed());
    }

    #[test]
    fn malformed_and_oversized_requests_fail_without_policy_details() {
        let pdp = fixture_pdp();

        let malformed = pdp.handle(request(b"not-json".to_vec()));
        let oversized = pdp.handle(request(vec![b' '; MAX_DOCUMENT_BYTES + 1]));

        assert_eq!(malformed.status(), StatusCode::BAD_REQUEST);
        assert!(malformed.body().is_empty());
        assert_eq!(oversized.status(), StatusCode::PAYLOAD_TOO_LARGE);
        assert!(oversized.body().is_empty());
    }

    #[test]
    fn endpoint_and_media_type_are_exact() {
        let pdp = fixture_pdp();
        let mut wrong_path = request(Vec::new());
        *wrong_path.uri_mut() = "/other".parse().expect("valid fixture URI");
        let mut wrong_type = request(Vec::new());
        wrong_type
            .headers_mut()
            .insert(CONTENT_TYPE, HeaderValue::from_static("text/plain"));

        assert_eq!(pdp.handle(wrong_path).status(), StatusCode::NOT_FOUND);
        assert_eq!(
            pdp.handle(wrong_type).status(),
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
    }

    fn fixture_pdp() -> CedarPdp {
        CedarPdp::new_validated(POLICY, SCHEMA, "[]", "policy-1", "cedar-4.11.2")
            .expect("fixture policy activates")
    }

    fn request(body: Vec<u8>) -> Request<Vec<u8>> {
        Request::builder()
            .method(Method::POST)
            .uri(ACCESS_EVALUATION_PATH)
            .header(CONTENT_TYPE, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .body(body)
            .expect("fixture request builds")
    }
}
