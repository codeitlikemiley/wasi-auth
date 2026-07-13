//! Deterministic terminal authentication broker for component tests.

#![deny(missing_docs)]

use serde::Deserialize;
use wasip3::wit_bindgen::StreamResult;
use wasip3::{
    clocks::monotonic_clock::wait_for,
    http::types::{ErrorCode, Headers, Method, Request, Response},
    wit_future, wit_stream,
};

struct Component;

const MAX_REQUEST_SIZE: usize = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BrokerRequestV1 {
    version: u8,
    service_id: String,
    audiences: Vec<String>,
    request_id: String,
}

wasip3::http::service::export!(Component);

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        let method = request.get_method();
        let path = request
            .get_path_with_query()
            .unwrap_or_else(|| "/".to_owned());
        if !matches!(method, Method::Post) || path.split('?').next() != Some("/authenticate") {
            return response(404, None);
        }

        let authorization = request.get_headers().get("authorization");
        let body = collect_request(request).await?;
        if authorization.is_empty() {
            return response(401, None);
        }
        if !valid_broker_request(&body) {
            return response(400, None);
        }
        match authorization.as_slice() {
            [value] if value == b"Bearer allow" => response(
                200,
                Some(
                    br#"{"version":1,"subject":"user-1","issuer":"middleware-secret-issuer-sentinel","scopes":["read","write"],"roles":["member"],"acr":"urn:example:loa:2","amr":["pwd"],"decision_id":"decision-allow","policy_revision":"mock-r1"}"#
                        .to_vec(),
                ),
            ),
            [value] if value == b"Bearer readonly" => response(
                200,
                Some(
                    br#"{"version":1,"subject":"user-readonly","issuer":"middleware-secret-issuer-sentinel","scopes":["read"],"roles":["viewer"],"acr":"urn:example:loa:2","amr":["pwd"],"decision_id":"decision-readonly","policy_revision":"mock-r1"}"#
                        .to_vec(),
                ),
            ),
            [value] if value == b"Bearer lowacr" => response(
                200,
                Some(
                    br#"{"version":1,"subject":"user-lowacr","issuer":"middleware-secret-issuer-sentinel","scopes":["read","write"],"roles":["member"],"acr":"urn:example:loa:1","amr":["pwd"],"decision_id":"decision-lowacr","policy_revision":"mock-r1"}"#
                        .to_vec(),
                ),
            ),
            [value] if value == b"Bearer no-relation" => response(
                200,
                Some(
                    br#"{"version":1,"subject":"user-no-relation","issuer":"middleware-secret-issuer-sentinel","scopes":["read","write"],"roles":["member"],"acr":"urn:example:loa:2","amr":["pwd"],"decision_id":"decision-no-relation","policy_revision":"mock-r1"}"#
                        .to_vec(),
                ),
            ),
            [value] if value == b"Bearer deny" => response(403, None),
            [value] if value == b"Bearer error" => response(500, None),
            [value] if value == b"Bearer slow" => slow_policy_response(),
            [value] if value == b"Bearer malformed" => response(200, Some(b"not-json".to_vec())),
            [value] if value == b"Bearer invalid-identity" => response(
                200,
                Some(
                    br#"{"version":1,"subject":"bad\r\nsubject","issuer":"issuer","scopes":["read"],"decision_id":"decision-invalid","policy_revision":"mock-r1"}"#
                        .to_vec(),
                ),
            ),
            [value] if value == b"Bearer limit-ok" => sized_policy_response(64 * 1024),
            [value] if value == b"Bearer limit-over" => sized_policy_response(64 * 1024 + 1),
            [_] => response(401, None),
            _ => response(400, None),
        }
    }
}

async fn collect_request(request: Request) -> Result<Vec<u8>, ErrorCode> {
    let (result_writer, body_result) = wit_future::new(|| Err(ErrorCode::InternalError(None)));
    let (mut body, trailers) = Request::consume_body(request, body_result);
    let mut output = Vec::new();
    loop {
        let (status, chunk) = body.read(Vec::with_capacity(8 * 1024)).await;
        if output.len().saturating_add(chunk.len()) > MAX_REQUEST_SIZE {
            return Err(ErrorCode::HttpRequestBodySize(Some(
                MAX_REQUEST_SIZE as u64,
            )));
        }
        output.extend_from_slice(&chunk);
        match status {
            StreamResult::Complete(_) => {}
            StreamResult::Dropped => {
                let _trailers = match trailers.await {
                    Ok(trailers) => trailers,
                    Err(error) => {
                        let _write_result = result_writer
                            .write(Err(ErrorCode::InternalError(None)))
                            .await;
                        return Err(error);
                    }
                };
                result_writer
                    .write(Ok(()))
                    .await
                    .map_err(|_| ErrorCode::InternalError(None))?;
                return Ok(output);
            }
            StreamResult::Cancelled => return Err(ErrorCode::InternalError(None)),
        }
    }
}

fn valid_broker_request(body: &[u8]) -> bool {
    let Ok(request) = serde_json::from_slice::<BrokerRequestV1>(body) else {
        return false;
    };
    request.version == 1
        && !request.service_id.is_empty()
        && !request.audiences.is_empty()
        && request
            .audiences
            .iter()
            .all(|audience| !audience.is_empty())
        && !request.request_id.is_empty()
}

fn sized_policy_response(size: usize) -> Result<Response, ErrorCode> {
    let mut body = br#"{"version":1,"subject":"sized-user","issuer":"issuer","scopes":["read"],"decision_id":"decision-sized","policy_revision":"mock-r1"}"#.to_vec();
    body.resize(size, b' ');
    response(200, Some(body))
}

fn slow_policy_response() -> Result<Response, ErrorCode> {
    let body =
        br#"{"version":1,"subject":"slow-user","issuer":"middleware-secret-issuer-sentinel","scopes":["read"],"decision_id":"decision-slow","policy_revision":"mock-r1"}"#
            .to_vec();
    let fields = vec![
        ("content-type".to_owned(), b"application/json".to_vec()),
        (
            "content-length".to_owned(),
            body.len().to_string().into_bytes(),
        ),
    ];
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let chunks = body.chunks(10).map(<[u8]>::to_vec).collect::<Vec<_>>();
    let (mut writer, reader) = wit_stream::new();
    let (body_result_writer, body_result) = wit_future::new(|| Err(ErrorCode::InternalError(None)));
    wasip3::spawn(async move {
        for (index, chunk) in chunks.into_iter().enumerate() {
            if index > 0 {
                wait_for(400_000_000).await;
            }
            let remaining = writer.write_all(chunk).await;
            if !remaining.is_empty() {
                return;
            }
        }
        drop(writer);
        let _write_result = body_result_writer.write(Ok(None)).await;
    });
    let (response, transmission_result) = Response::new(headers, Some(reader), body_result);
    wasip3::spawn(async move {
        let _result = transmission_result.await;
    });
    Ok(response)
}

fn response(status: u16, body: Option<Vec<u8>>) -> Result<Response, ErrorCode> {
    let body_length = body.as_ref().map_or(0, Vec::len);
    let fields = vec![
        ("content-type".to_owned(), b"application/json".to_vec()),
        (
            "content-length".to_owned(),
            body_length.to_string().into_bytes(),
        ),
    ];
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let (body, body_result) = if let Some(body) = body {
        let (mut writer, reader) = wit_stream::new();
        let (body_result_writer, body_result) =
            wit_future::new(|| Err(ErrorCode::InternalError(None)));
        wasip3::spawn(async move {
            let remaining = writer.write_all(body).await;
            if remaining.is_empty() {
                drop(writer);
                let _write_result = body_result_writer.write(Ok(None)).await;
            }
        });
        (Some(reader), body_result)
    } else {
        let (body_result_writer, body_result) = wit_future::new(|| Ok(None));
        drop(body_result_writer);
        (None, body_result)
    };
    let (response, transmission_result) = Response::new(headers, body, body_result);
    wasip3::spawn(async move {
        let _result = transmission_result.await;
    });
    response
        .set_status_code(status)
        .map_err(|()| ErrorCode::InternalError(None))?;
    Ok(response)
}
