//! Deterministic terminal `WASIp3` service for middleware composition tests.

#![deny(missing_docs)]

use http::HeaderValue;
use wasi_http_metadata::{AUTH_CONTEXT_HEADER, AuthContextV1, AuthStateV1, decode_auth_context};
use wasip3::{
    clocks::monotonic_clock::wait_for,
    http::types::{ErrorCode, Headers, Method, Request, Response},
    wit_future, wit_stream,
};

struct Component;

wasip3::http::service::export!(Component);

impl wasip3::exports::http::handler::Guest for Component {
    async fn handle(request: Request) -> Result<Response, ErrorCode> {
        if request.get_headers().has("x-wasi-test-count") {
            eprintln!("wasi-http-middleware-test: terminal-invocation");
        }
        let method = request.get_method();
        let path = request
            .get_path_with_query()
            .unwrap_or_else(|| "/".to_owned());
        let path = path.split('?').next().unwrap_or("/");

        match (&method, path) {
            (Method::Get | Method::Head, "/") => {
                let body = matches!(method, Method::Get).then(|| b"echo-service\n".to_vec());
                response(200, vec![], body)
            }
            (_, "/echo") => echo_body(request),
            (Method::Get, "/identity") => {
                let headers = request.get_headers();
                let subject = parse_context(&headers)
                    .and_then(|context| {
                        context
                            .principal()
                            .map(|principal| principal.subject().to_owned())
                    })
                    .unwrap_or_else(|| "anonymous".to_owned());
                response(200, vec![], Some(subject.into_bytes()))
            }
            (Method::Get, "/auth-contract") => auth_contract(&request),
            (Method::Get, "/redirect") => {
                response(302, vec![("location".to_owned(), b"/".to_vec())], None)
            }
            (Method::Get | Method::Head, "/method") => response(
                200,
                vec![("allow".to_owned(), b"GET, HEAD".to_vec())],
                matches!(method, Method::Get).then(|| b"method allowed\n".to_vec()),
            ),
            (_, "/method") => {
                response(405, vec![("allow".to_owned(), b"GET, HEAD".to_vec())], None)
            }
            (_, "/too-large") => response(413, vec![], None),
            (_, "/error") => response(500, vec![], None),
            (Method::Get, "/delayed") => delayed_response(),
            (Method::Get, "/failing-stream") => failing_stream_response(),
            (Method::Get, "/immediate-failure") => immediate_failure_response(),
            (Method::Get, "/trailers") => trailers_response(),
            _ => response(404, vec![], None),
        }
    }
}

fn auth_contract(request: &Request) -> Result<Response, ErrorCode> {
    let headers = request.get_headers();
    let fields = headers.copy_all();
    let reserved_spoof = fields
        .iter()
        .any(|(name, _)| name.starts_with("x-wasi-auth-") && name != AUTH_CONTEXT_HEADER.as_str());
    if headers.has("authorization") || reserved_spoof {
        return response(
            500,
            vec![],
            Some(b"credential-or-spoof-reached-terminal\n".to_vec()),
        );
    }
    let values = headers.get(AUTH_CONTEXT_HEADER.as_str());
    let [encoded] = values.as_slice() else {
        return response(500, vec![], Some(b"invalid-auth-context\n".to_vec()));
    };
    let Some(context) = HeaderValue::from_bytes(encoded)
        .ok()
        .and_then(|value| decode_auth_context(&value).ok())
    else {
        return response(500, vec![], Some(b"invalid-auth-context\n".to_vec()));
    };
    let state = match context.state() {
        AuthStateV1::Anonymous => b"anonymous\n".to_vec(),
        AuthStateV1::Authenticated => b"authenticated\n".to_vec(),
        _ => return response(500, vec![], Some(b"unknown-auth-state\n".to_vec())),
    };
    response(
        200,
        vec![
            (AUTH_CONTEXT_HEADER.as_str().to_owned(), encoded.clone()),
            ("x-wasi-auth-spoofed".to_owned(), b"terminal".to_vec()),
        ],
        Some(state),
    )
}

fn parse_context(headers: &Headers) -> Option<AuthContextV1> {
    let values = headers.get(AUTH_CONTEXT_HEADER.as_str());
    let [value] = values.as_slice() else {
        return None;
    };
    HeaderValue::from_bytes(value)
        .ok()
        .and_then(|value| decode_auth_context(&value).ok())
}

fn delayed_response() -> Result<Response, ErrorCode> {
    let fields = vec![("content-type".to_owned(), b"text/plain".to_vec())];
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let (mut writer, reader) = wit_stream::new();
    let (body_result_writer, body_result) = wit_future::new(|| Err(ErrorCode::InternalError(None)));
    wasip3::spawn(async move {
        let remaining = writer.write_all(b"first\n".to_vec()).await;
        if !remaining.is_empty() {
            return;
        }
        wait_for(300_000_000).await;
        let remaining = writer.write_all(b"second\n".to_vec()).await;
        if remaining.is_empty() {
            drop(writer);
            let _write_result = body_result_writer.write(Ok(None)).await;
        }
    });
    let (response, transmission_result) = Response::new(headers, Some(reader), body_result);
    wasip3::spawn(async move {
        let _result = transmission_result.await;
    });
    Ok(response)
}

fn failing_stream_response() -> Result<Response, ErrorCode> {
    let fields = vec![("content-type".to_owned(), b"text/plain".to_vec())];
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let (mut writer, reader) = wit_stream::new();
    let (body_result_writer, body_result) = wit_future::new(|| Err(ErrorCode::InternalError(None)));
    wasip3::spawn(async move {
        let remaining = writer.write_all(b"partial body\n".to_vec()).await;
        if remaining.is_empty() {
            // Make this an observably mid-stream failure rather than a race
            // between buffered frame delivery and connection termination.
            wait_for(50_000_000).await;
            drop(writer);
            let _write_result = body_result_writer
                .write(Err(ErrorCode::InternalError(None)))
                .await;
        }
    });
    let (response, transmission_result) = Response::new(headers, Some(reader), body_result);
    wasip3::spawn(async move {
        let _result = transmission_result.await;
    });
    Ok(response)
}

fn immediate_failure_response() -> Result<Response, ErrorCode> {
    let fields = vec![("content-type".to_owned(), b"text/plain".to_vec())];
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let (body_result_writer, body_result) = wit_future::new(|| Err(ErrorCode::InternalError(None)));
    drop(body_result_writer);
    let (response, transmission_result) = Response::new(headers, None, body_result);
    wasip3::spawn(async move {
        let _result = transmission_result.await;
    });
    Ok(response)
}

fn trailers_response() -> Result<Response, ErrorCode> {
    let fields = vec![("content-type".to_owned(), b"text/plain".to_vec())];
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let (mut writer, reader) = wit_stream::new();
    let (body_result_writer, body_result) = wit_future::new(|| Err(ErrorCode::InternalError(None)));
    wasip3::spawn(async move {
        let remaining = writer.write_all(b"body with trailer\n".to_vec()).await;
        if remaining.is_empty() {
            drop(writer);
            let _write_result = body_result_writer.write(echo_trailers()).await;
        }
    });
    let (response, transmission_result) = Response::new(headers, Some(reader), body_result);
    wasip3::spawn(async move {
        let _result = transmission_result.await;
    });
    Ok(response)
}

fn echo_trailers() -> Result<Option<Headers>, ErrorCode> {
    let trailer_fields = vec![("x-echo-trailer".to_owned(), b"preserved".to_vec())];
    Headers::from_list(&trailer_fields)
        .map(Some)
        .map_err(|_| ErrorCode::HttpResponseTrailerSectionSize(None))
}

fn echo_body(request: Request) -> Result<Response, ErrorCode> {
    let content_length = request.get_headers().get("content-length");
    let (request_result_writer, request_result) =
        wit_future::new(|| Err(ErrorCode::InternalError(None)));
    let (body, trailers) = Request::consume_body(request, request_result);
    let mut fields = vec![(
        "content-type".to_owned(),
        b"application/octet-stream".to_vec(),
    )];
    if let [value] = content_length.as_slice() {
        fields.push(("content-length".to_owned(), value.clone()));
    }
    let headers =
        Headers::from_list(&fields).map_err(|_| ErrorCode::HttpResponseHeaderSectionSize(None))?;
    let (response, transmission_result) = Response::new(headers, Some(body), trailers);
    wasip3::spawn(async move {
        let result = transmission_result.await;
        let _write_result = request_result_writer.write(result).await;
    });
    Ok(response)
}

fn response(
    status: u16,
    mut fields: Vec<(String, Vec<u8>)>,
    body: Option<Vec<u8>>,
) -> Result<Response, ErrorCode> {
    let body_length = body.as_ref().map_or(0, Vec::len);
    fields.push((
        "content-length".to_owned(),
        body_length.to_string().into_bytes(),
    ));
    if body.is_some() {
        fields.push(("content-type".to_owned(), b"text/plain".to_vec()));
    }
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
