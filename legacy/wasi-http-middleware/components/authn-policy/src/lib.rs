//! Strict fail-closed authentication backed by an external broker.

#![deny(missing_docs)]

use std::sync::OnceLock;

use http::header::AUTHORIZATION;
use wasi_http_authn_runtime::{
    AuthnConfig, AuthnConfigError, AuthnOutcome, AuthnRejection, authenticate_with_diagnostics,
};
use wasi_http_metadata::{AUTH_CONTEXT_HEADER, REQUEST_ID_HEADER};
use wasi_http_middleware_component_support::{
    Header, diagnostic_stage, empty_response, generated_request_id, remove_header,
    remove_headers_with_prefix, replace_request_headers, replace_response_headers, request_headers,
    response_headers, set_header, to_header_map,
};
use wasi_http_policy_core::RequestIdPolicy;
use wasip3::{
    cli::environment::get_environment,
    http::types::{ErrorCode, Request, Response},
};

#[allow(unknown_lints, missing_docs, clippy::same_length_and_capacity)]
mod bindings {
    wasi_http_middleware_component_support::generate_middleware_bindings!("../../wit");
}

use bindings::wasi::http::handler;

static CONFIG: OnceLock<Result<AuthnConfig, AuthnConfigError>> = OnceLock::new();

struct Component;

bindings::export!(Component with_types_in bindings);

impl bindings::exports::wasi::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let fields = request_headers(&request);
        let Ok(headers) = to_header_map(&fields) else {
            return empty_response(400, Vec::new());
        };
        let request_id = canonical_request_id(&headers)?;
        let Ok(config) = CONFIG
            .get_or_init(|| AuthnConfig::from_environment(&get_environment()))
            .as_ref()
        else {
            diagnostic_stage("authn_config");
            return configuration_failure_response(&request_id);
        };

        let (outcome, stage) = authenticate_with_diagnostics(&headers, &request_id, config).await;
        if let Some(stage) = stage {
            diagnostic_stage(stage.as_str());
        }
        match outcome {
            AuthnOutcome::Pass(context) => {
                let mut fields = fields;
                remove_header(&mut fields, AUTHORIZATION.as_str());
                remove_headers_with_prefix(&mut fields, "x-wasi-auth-");
                set_header(
                    &mut fields,
                    AUTH_CONTEXT_HEADER.as_str(),
                    context.as_bytes(),
                );
                set_header(
                    &mut fields,
                    REQUEST_ID_HEADER.as_str(),
                    request_id.as_bytes(),
                );
                let request = replace_request_headers(request, &fields)?;
                let response = handler::handle(request).await?;
                strip_response_auth_headers(response)
            }
            AuthnOutcome::Reject(rejection) => {
                rejection_response(rejection, config.service_id(), &request_id)
            }
            _ => rejection_response(
                AuthnRejection::Unavailable,
                config.service_id(),
                &request_id,
            ),
        }
    }
}

fn strip_response_auth_headers(response: Response) -> Result<Response, ErrorCode> {
    let mut fields = response_headers(&response);
    remove_headers_with_prefix(&mut fields, "x-wasi-auth-");
    replace_response_headers(response, &fields)
}

fn configuration_failure_response(request_id: &str) -> Result<Response, ErrorCode> {
    empty_response(
        503,
        vec![
            (
                REQUEST_ID_HEADER.as_str().to_owned(),
                request_id.as_bytes().to_vec(),
            ),
            ("retry-after".to_owned(), b"1".to_vec()),
        ],
    )
}

fn canonical_request_id(headers: &http::HeaderMap) -> Result<String, ErrorCode> {
    RequestIdPolicy
        .canonicalize(headers, generated_request_id)
        .map_err(|_| ErrorCode::InternalError(None))
}

fn rejection_response(
    rejection: AuthnRejection,
    realm: &str,
    request_id: &str,
) -> Result<Response, ErrorCode> {
    let mut headers: Vec<Header> = vec![(
        REQUEST_ID_HEADER.as_str().to_owned(),
        request_id.as_bytes().to_vec(),
    )];
    if let Some(challenge) = rejection.bearer_challenge(realm) {
        headers.push(("www-authenticate".to_owned(), challenge.into_bytes()));
    }
    if rejection == AuthnRejection::Unavailable {
        headers.push(("retry-after".to_owned(), b"1".to_vec()));
    }
    empty_response(rejection.status(), headers)
}
