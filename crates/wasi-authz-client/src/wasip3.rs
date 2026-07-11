//! WASIp3 `wasi:http/client` transport.

use http::Request;
#[cfg(target_arch = "wasm32")]
use http::Response;

use crate::{
    DEFAULT_TIMEOUT_NANOS, HttpTransport, TransportConfigError, TransportError, TransportFuture,
    timeout_nanos,
};

/// WASIp3 outbound HTTP transport supplied by the component host.
#[derive(Clone, Copy, Debug)]
pub struct Wasip3Transport {
    timeout_nanos: u64,
}

impl Default for Wasip3Transport {
    fn default() -> Self {
        Self {
            timeout_nanos: DEFAULT_TIMEOUT_NANOS,
        }
    }
}

impl Wasip3Transport {
    /// Constructs a transport with a default two-second absolute deadline.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the absolute and per-phase provider deadline.
    ///
    /// # Errors
    ///
    /// Returns [`TransportConfigError`] unless the timeout is between one
    /// millisecond and sixty seconds.
    pub fn with_timeout(
        mut self,
        timeout: std::time::Duration,
    ) -> Result<Self, TransportConfigError> {
        self.timeout_nanos = timeout_nanos(timeout)?;
        Ok(self)
    }
}

impl HttpTransport for Wasip3Transport {
    fn send<'a>(&'a self, request: Request<Vec<u8>>) -> TransportFuture<'a> {
        #[cfg(target_arch = "wasm32")]
        {
            let timeout_nanos = self.timeout_nanos;
            Box::pin(send_with_deadline(request, timeout_nanos))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = request;
            Box::pin(async { Err(TransportError::UnsupportedTarget) })
        }
    }
}

#[cfg(target_arch = "wasm32")]
async fn send_with_deadline(
    request: Request<Vec<u8>>,
    timeout_nanos: u64,
) -> Result<Response<Vec<u8>>, TransportError> {
    use futures::future::{Either, select};

    let operation = Box::pin(send_request(request, timeout_nanos));
    let deadline = Box::pin(wasip3::clocks::monotonic_clock::wait_for(timeout_nanos));
    match select(operation, deadline).await {
        Either::Left((result, _deadline)) => result,
        Either::Right(((), _operation)) => Err(TransportError::Timeout),
    }
}

#[cfg(target_arch = "wasm32")]
async fn send_request(
    request: Request<Vec<u8>>,
    timeout_nanos: u64,
) -> Result<Response<Vec<u8>>, TransportError> {
    use wasip3::{
        http::{
            client,
            types::{Request as WasiRequest, RequestOptions, Scheme},
        },
        wit_future, wit_stream,
    };

    let (parts, body) = request.into_parts();
    let headers = request_headers(&parts.headers)?;
    let options = RequestOptions::new();
    options
        .set_connect_timeout(Some(timeout_nanos))
        .map_err(|_| TransportError::Protocol)?;
    options
        .set_first_byte_timeout(Some(timeout_nanos))
        .map_err(|_| TransportError::Protocol)?;
    options
        .set_between_bytes_timeout(Some(timeout_nanos))
        .map_err(|_| TransportError::Protocol)?;
    let (mut body_writer, body_reader) = wit_stream::new();
    let (body_result_writer, body_result) =
        wit_future::new(|| Err(wasip3::http::types::ErrorCode::InternalError(None)));
    let (request, transmission_result) =
        WasiRequest::new(headers, Some(body_reader), body_result, Some(options));
    let method = request_method(&parts.method);
    let scheme = match parts.uri.scheme_str() {
        Some("http") => Scheme::Http,
        Some("https") => Scheme::Https,
        _ => return Err(TransportError::Protocol),
    };
    let authority = parts
        .uri
        .authority()
        .map(http::uri::Authority::as_str)
        .ok_or(TransportError::Protocol)?;
    let path_with_query = parts
        .uri
        .path_and_query()
        .map(http::uri::PathAndQuery::as_str)
        .ok_or(TransportError::Protocol)?;
    request
        .set_method(&method)
        .and_then(|()| request.set_scheme(Some(&scheme)))
        .and_then(|()| request.set_authority(Some(authority)))
        .and_then(|()| request.set_path_with_query(Some(path_with_query)))
        .map_err(|()| TransportError::Protocol)?;

    let write_body = async move {
        let remaining = body_writer.write_all(body).await;
        if !remaining.is_empty() {
            return Err(TransportError::Canceled);
        }
        drop(body_writer);
        body_result_writer
            .write(Ok(None))
            .await
            .map_err(|_| TransportError::Canceled)
    };
    let send_and_collect = async move {
        let response = client::send(request).await.map_err(map_error_code)?;
        collect_response(response).await
    };
    let await_transmission = async move { transmission_result.await.map_err(map_error_code) };
    let (response, (), ()) = futures::try_join!(send_and_collect, write_body, await_transmission)?;
    Ok(response)
}

#[cfg(target_arch = "wasm32")]
fn request_headers(
    headers: &http::HeaderMap,
) -> Result<wasip3::http::types::Headers, TransportError> {
    let mut fields = Vec::with_capacity(headers.len());
    for name in headers.keys() {
        for value in headers.get_all(name) {
            fields.push((name.as_str().to_owned(), value.as_bytes().to_vec()));
        }
    }
    wasip3::http::types::Headers::from_list(&fields).map_err(|_| TransportError::Protocol)
}

#[cfg(target_arch = "wasm32")]
fn request_method(method: &http::Method) -> wasip3::http::types::Method {
    use wasip3::http::types::Method;

    match *method {
        http::Method::GET => Method::Get,
        http::Method::HEAD => Method::Head,
        http::Method::POST => Method::Post,
        http::Method::PUT => Method::Put,
        http::Method::DELETE => Method::Delete,
        http::Method::CONNECT => Method::Connect,
        http::Method::OPTIONS => Method::Options,
        http::Method::TRACE => Method::Trace,
        http::Method::PATCH => Method::Patch,
        _ => Method::Other(method.as_str().to_owned()),
    }
}

#[cfg(target_arch = "wasm32")]
async fn collect_response(
    response: wasip3::http::types::Response,
) -> Result<Response<Vec<u8>>, TransportError> {
    use wasi_authz_contract::MAX_DOCUMENT_BYTES;
    use wasip3::{http::types::ErrorCode, wit_bindgen::StreamResult, wit_future};

    let response_status = http::StatusCode::from_u16(response.get_status_code())
        .map_err(|_| TransportError::Protocol)?;
    let fields = response.get_headers().copy_all();
    let content_length = declared_content_length(&fields)?;
    let mut headers = http::HeaderMap::new();
    for (name, value) in fields {
        let name =
            http::HeaderName::from_bytes(name.as_bytes()).map_err(|_| TransportError::Protocol)?;
        let mut value =
            http::HeaderValue::from_bytes(&value).map_err(|_| TransportError::Protocol)?;
        if is_sensitive_header(&name) {
            value.set_sensitive(true);
        }
        headers.append(name, value);
    }

    let (result_writer, body_result) = wit_future::new(|| Err(ErrorCode::InternalError(None)));
    let (mut body, trailers) = wasip3::http::types::Response::consume_body(response, body_result);
    let mut collected = Vec::new();
    loop {
        let (stream_status, chunk) = body.read(Vec::with_capacity(8 * 1024)).await;
        if collected.len().saturating_add(chunk.len()) > MAX_DOCUMENT_BYTES {
            return Err(TransportError::ResponseTooLarge);
        }
        collected.extend_from_slice(&chunk);
        match stream_status {
            StreamResult::Complete(_) => {}
            StreamResult::Dropped => {
                // Provider trailers do not participate in authorization and
                // are discarded, but their completion must still be observed
                // so the host can release the response lifecycle and pooled
                // connection. The outer race keeps this wait under the same
                // absolute operation deadline.
                let _trailers = trailers.await.map_err(map_error_code)?;
                result_writer
                    .write(Ok(()))
                    .await
                    .map_err(|_| TransportError::Canceled)?;
                validate_content_length(content_length, collected.len())?;
                return Ok(response_from_parts(response_status, headers, collected));
            }
            StreamResult::Cancelled => return Err(TransportError::Canceled),
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn declared_content_length(headers: &[(String, Vec<u8>)]) -> Result<Option<usize>, TransportError> {
    let mut declared = None;
    for (name, value) in headers {
        if !name.eq_ignore_ascii_case(http::header::CONTENT_LENGTH.as_str()) {
            continue;
        }
        if declared.is_some() {
            return Err(TransportError::Protocol);
        }
        let value = std::str::from_utf8(value)
            .map_err(|_| TransportError::Protocol)?
            .trim();
        if value.is_empty() || !value.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(TransportError::Protocol);
        }
        let value = value
            .parse::<u64>()
            .map_err(|_| TransportError::ResponseTooLarge)?;
        if value > wasi_authz_contract::MAX_DOCUMENT_BYTES as u64 {
            return Err(TransportError::ResponseTooLarge);
        }
        declared = Some(usize::try_from(value).map_err(|_| TransportError::ResponseTooLarge)?);
    }
    Ok(declared)
}

#[cfg(any(target_arch = "wasm32", test))]
fn validate_content_length(
    declared: Option<usize>,
    collected: usize,
) -> Result<(), TransportError> {
    if declared.is_some_and(|length| length != collected) {
        return Err(TransportError::Protocol);
    }
    Ok(())
}

#[cfg(target_arch = "wasm32")]
fn response_from_parts(
    status: http::StatusCode,
    headers: http::HeaderMap,
    body: Vec<u8>,
) -> Response<Vec<u8>> {
    let mut response = Response::new(body);
    *response.status_mut() = status;
    *response.headers_mut() = headers;
    response
}

#[cfg(target_arch = "wasm32")]
fn is_sensitive_header(name: &http::HeaderName) -> bool {
    matches!(
        name.as_str(),
        "authorization" | "proxy-authorization" | "cookie" | "set-cookie"
    ) || name.as_str().starts_with("x-wasi-auth-")
}

#[cfg(target_arch = "wasm32")]
fn map_error_code(error: wasip3::http::types::ErrorCode) -> TransportError {
    use wasip3::http::types::ErrorCode;

    if matches!(
        error,
        ErrorCode::DnsTimeout
            | ErrorCode::ConnectionTimeout
            | ErrorCode::ConnectionReadTimeout
            | ErrorCode::ConnectionWriteTimeout
            | ErrorCode::HttpResponseTimeout
    ) {
        TransportError::Timeout
    } else {
        TransportError::Unavailable
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn native_target_fails_explicitly() {
        let request = Request::builder()
            .uri("https://pdp.example/access/v1/evaluation")
            .body(Vec::new())
            .expect("request builds");

        let result = block_on(Wasip3Transport::new().send(request));

        assert!(matches!(result, Err(TransportError::UnsupportedTarget)));
    }

    #[test]
    fn content_length_is_single_strict_bounded_and_exact() {
        assert_eq!(
            declared_content_length(&[("content-length".to_owned(), b" 42 ".to_vec(),)]),
            Ok(Some(42))
        );
        assert_eq!(
            declared_content_length(&[
                ("content-length".to_owned(), b"42".to_vec()),
                ("Content-Length".to_owned(), b"42".to_vec()),
            ]),
            Err(TransportError::Protocol)
        );
        assert_eq!(
            declared_content_length(&[("content-length".to_owned(), b"4, 4".to_vec(),)]),
            Err(TransportError::Protocol)
        );
        assert_eq!(
            declared_content_length(&[(
                "content-length".to_owned(),
                (wasi_authz_contract::MAX_DOCUMENT_BYTES + 1)
                    .to_string()
                    .into_bytes(),
            )]),
            Err(TransportError::ResponseTooLarge)
        );
        assert_eq!(
            validate_content_length(Some(42), 41),
            Err(TransportError::Protocol)
        );
        assert_eq!(validate_content_length(Some(42), 42), Ok(()));
        assert_eq!(validate_content_length(None, 42), Ok(()));
    }

    #[cfg(not(target_arch = "wasm32"))]
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
