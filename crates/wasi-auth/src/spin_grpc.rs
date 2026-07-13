//! Spin gRPC request classification and bounded stream policy.
//!
//! Spin serves Tonic through its ordinary HTTP trigger. This module therefore
//! depends only on `http`; the application calls `spin_sdk::http::grpc::serve`
//! after classifying the request.

use bytes::Buf;
use http::Request;
use http::header::{CONTENT_TYPE, HeaderValue};
use http_body::{Body, Frame, SizeHint};
use std::future::poll_fn;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use thiserror::Error;

use crate::context::{VerifiedAuthContext, VerifiedRequestContext};

type BodyFramePoll<D, E> = Poll<Option<Result<Frame<D>, E>>>;

/// Default maximum decoded gRPC message size.
pub const DEFAULT_MAX_GRPC_MESSAGE_BYTES: usize = 256 * 1024;
/// Default maximum inbound messages per client or bidirectional stream.
pub const DEFAULT_MAX_INBOUND_STREAM_MESSAGES: usize = 100;
/// Default maximum stream lifetime in seconds before cursor-based reconnect.
pub const DEFAULT_MAX_STREAM_SECONDS: u64 = 5 * 60;

/// Response body returned by [`normalize_trailers_only_response`].
///
/// The wrapper replays a first data frame when the compatibility check had to
/// poll it. Trailers-only responses are promoted into the initial HTTP header
/// block and therefore use an empty body.
pub struct GrpcResponseBody<B>
where
    B: Body,
{
    first: Option<Frame<B::Data>>,
    body: Option<B>,
}

impl<B> Body for GrpcResponseBody<B>
where
    B: Body + Unpin,
    B::Data: Unpin,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(frame) = this.first.take() {
            return Poll::Ready(Some(Ok(frame)));
        }

        match this.body.as_mut() {
            Some(body) => Pin::new(body).poll_frame(context),
            None => Poll::Ready(None),
        }
    }

    fn is_end_stream(&self) -> bool {
        self.first.is_none() && self.body.as_ref().is_none_or(Body::is_end_stream)
    }

    fn size_hint(&self) -> SizeHint {
        if self.first.is_some() {
            SizeHint::default()
        } else {
            self.body
                .as_ref()
                .map_or_else(SizeHint::default, Body::size_hint)
        }
    }
}

/// Promotes a ready trailers-only Tonic response into HTTP response headers.
///
/// Final-WASI HTTP represents response trailers separately from the byte
/// stream. Some Spin SDK/runtime combinations currently close a response whose
/// first frame is trailers before forwarding those trailers. A gRPC error then
/// reaches clients as `Internal: server closed the stream without sending
/// trailers`. This adapter performs one non-blocking poll. If Tonic has already
/// produced a trailers-only status, the status metadata is moved into the
/// initial header block, which is the gRPC trailers-only wire representation.
/// Data and pending streaming responses remain streaming and are not buffered.
#[must_use]
pub fn normalize_trailers_only_response<B>(
    response: http::Response<B>,
) -> http::Response<GrpcResponseBody<B>>
where
    B: Body + Unpin,
    B::Data: Unpin,
{
    let (parts, mut body) = response.into_parts();
    let wake_flag = Arc::new(WakeFlag::default());
    let waker = Waker::from(Arc::clone(&wake_flag));
    let mut context = Context::from_waker(&waker);
    let mut immediate_repolls = 0_u8;
    let mut discarded_empty_frames = 0_u8;

    let first_poll = loop {
        wake_flag.woken.store(false, Ordering::Release);
        let poll = Pin::new(&mut body).poll_frame(&mut context);
        if is_empty_data_poll(&poll) && discarded_empty_frames < 8 {
            discarded_empty_frames += 1;
            continue;
        }
        let requested_repoll = wake_flag.woken.swap(false, Ordering::AcqRel);
        if !matches!(poll, Poll::Pending) || !requested_repoll || immediate_repolls >= 8 {
            break poll;
        }
        immediate_repolls += 1;
    };

    finish_normalization(parts, body, first_poll)
}

/// Promotes a trailers-only Tonic response after awaiting its first body frame.
///
/// Use this variant for unary and client-streaming RPCs, whose response must
/// terminate with one message or a status. Do not use it for event-driven
/// server streams that are allowed to remain idle before their first message;
/// awaiting the first frame would intentionally delay their response headers.
#[must_use]
pub async fn normalize_trailers_only_response_awaiting_first_frame<B>(
    response: http::Response<B>,
) -> http::Response<GrpcResponseBody<B>>
where
    B: Body + Unpin,
    B::Data: Unpin,
{
    let (parts, mut body) = response.into_parts();
    let mut discarded_empty_frames = 0_u8;
    let first_poll = loop {
        let poll = Poll::Ready(poll_fn(|context| Pin::new(&mut body).poll_frame(context)).await);
        if is_empty_data_poll(&poll) && discarded_empty_frames < 8 {
            discarded_empty_frames += 1;
            continue;
        }
        break poll;
    };
    finish_normalization(parts, body, first_poll)
}

fn is_empty_data_poll<D, E>(poll: &BodyFramePoll<D, E>) -> bool
where
    D: Buf,
{
    matches!(
        poll,
        Poll::Ready(Some(Ok(frame)))
            if frame.data_ref().is_some_and(|data| !data.has_remaining())
    )
}

fn finish_normalization<B>(
    mut parts: http::response::Parts,
    body: B,
    first_poll: BodyFramePoll<B::Data, B::Error>,
) -> http::Response<GrpcResponseBody<B>>
where
    B: Body + Unpin,
    B::Data: Unpin,
{
    let (first, body) = match first_poll {
        Poll::Pending => (None, Some(body)),
        Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => {
            let trailers = frame
                .into_trailers()
                .unwrap_or_else(|_| unreachable!("frame was checked as trailers"));
            parts.headers.extend(trailers);
            if !parts.headers.contains_key("grpc-status") {
                parts
                    .headers
                    .insert("grpc-status", HeaderValue::from_static("0"));
            }
            (None, None)
        }
        Poll::Ready(Some(Ok(frame))) => (Some(frame), Some(body)),
        Poll::Ready(Some(Err(_))) => {
            parts
                .headers
                .insert("grpc-status", HeaderValue::from_static("13"));
            parts.headers.insert(
                "grpc-message",
                HeaderValue::from_static("response%20body%20failed%20before%20its%20first%20frame"),
            );
            (None, None)
        }
        Poll::Ready(None) => {
            if !parts.headers.contains_key("grpc-status") {
                parts
                    .headers
                    .insert("grpc-status", HeaderValue::from_static("0"));
            }
            (None, None)
        }
    };

    http::Response::from_parts(parts, GrpcResponseBody { first, body })
}

/// Converts a normalized gRPC response into the final-WASI HTTP response.
///
/// Trailers-only responses use `contents = none` and move the status metadata
/// into the final-WASI trailers future. This avoids relying on Spin to infer a
/// terminal gRPC status from an empty byte stream. Other responses retain the
/// standard streaming body conversion.
///
/// # Errors
///
/// Returns a WASI HTTP error when response headers cannot be represented by the
/// final-WASI HTTP types or the ordinary streaming conversion fails.
pub fn into_final_wasi_response<B>(
    response: http::Response<GrpcResponseBody<B>>,
) -> Result<wasip3::http::types::Response, wasip3::http::types::ErrorCode>
where
    B: Body + Unpin + 'static,
    B::Data: Into<Vec<u8>> + Unpin,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync + 'static>>,
{
    if response.body().is_end_stream() && response.headers().contains_key("grpc-status") {
        let (mut parts, _body) = response.into_parts();
        let mut trailer_headers = http::HeaderMap::new();
        for name in ["grpc-status", "grpc-message", "grpc-status-details-bin"] {
            if let Some(value) = parts.headers.remove(name) {
                trailer_headers.insert(name, value);
            }
        }
        let headers = parts.headers.try_into().map_err(|error| {
            wasip3::http::types::ErrorCode::InternalError(Some(format!(
                "invalid gRPC response headers: {error}"
            )))
        })?;
        let trailers = trailer_headers.try_into().map_err(|error| {
            wasip3::http::types::ErrorCode::InternalError(Some(format!(
                "invalid gRPC response trailers: {error}"
            )))
        })?;
        let (trailers_writer, trailers_reader) = wasip3::wit_future::new(|| Ok(None));
        let (response, _transmission) =
            wasip3::http::types::Response::new(headers, None, trailers_reader);
        wasip3::wit_bindgen::spawn(async move {
            _ = trailers_writer.write(Ok(Some(trailers))).await;
        });
        response
            .set_status_code(parts.status.as_u16())
            .map_err(|()| {
                wasip3::http::types::ErrorCode::InternalError(Some(
                    "invalid gRPC HTTP status code".to_string(),
                ))
            })?;
        return Ok(response);
    }

    wasip3::http_compat::http_into_wasi_response(response)
}

#[derive(Default)]
struct WakeFlag {
    woken: AtomicBool,
}

impl Wake for WakeFlag {
    fn wake(self: Arc<Self>) {
        self.woken.store(true, Ordering::Release);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.woken.store(true, Ordering::Release);
    }
}

/// Validated limits for a streaming RPC.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StreamLimits {
    max_message_bytes: usize,
    max_inbound_messages: usize,
    max_duration_seconds: u64,
}

impl StreamLimits {
    /// Returns the production default stream limits.
    #[must_use]
    pub const fn production_default() -> Self {
        Self {
            max_message_bytes: DEFAULT_MAX_GRPC_MESSAGE_BYTES,
            max_inbound_messages: DEFAULT_MAX_INBOUND_STREAM_MESSAGES,
            max_duration_seconds: DEFAULT_MAX_STREAM_SECONDS,
        }
    }

    /// Returns the maximum decoded message size.
    #[must_use]
    pub const fn max_message_bytes(self) -> usize {
        self.max_message_bytes
    }

    /// Returns the maximum accepted inbound message count.
    #[must_use]
    pub const fn max_inbound_messages(self) -> usize {
        self.max_inbound_messages
    }

    /// Returns the maximum stream lifetime.
    #[must_use]
    pub const fn max_duration_seconds(self) -> u64 {
        self.max_duration_seconds
    }
}

impl Default for StreamLimits {
    fn default() -> Self {
        Self::production_default()
    }
}

/// gRPC trusted-context or stream-limit failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum GrpcBoundaryError {
    /// Native trusted ingress did not install context before gRPC dispatch.
    #[error("verified gRPC authentication context is missing")]
    MissingContext,
    /// The inbound stream exceeded its message bound.
    #[error("gRPC stream exceeds its inbound message limit")]
    TooManyMessages,
    /// A decoded message exceeded its byte bound.
    #[error("gRPC message exceeds its configured byte limit")]
    MessageTooLarge,
}

/// Returns whether a Spin HTTP request should be dispatched to Tonic.
///
/// Service prefixes are canonical paths such as `/auth.v1.AuthService/`.
#[must_use]
pub fn is_grpc_request<B>(request: &Request<B>, service_prefixes: &[&str]) -> bool {
    service_prefixes
        .iter()
        .any(|prefix| request.uri().path().starts_with(prefix))
        || request
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| value.starts_with("application/grpc"))
}

/// Returns the verified context inserted by native ingress.
///
/// # Errors
///
/// Returns [`GrpcBoundaryError::MissingContext`] when dispatch bypassed ingress.
pub fn verified_context<B>(
    request: &Request<B>,
) -> Result<&VerifiedAuthContext, GrpcBoundaryError> {
    request
        .extensions()
        .get::<VerifiedAuthContext>()
        .ok_or(GrpcBoundaryError::MissingContext)
}

/// Returns identity and current authorization facts inserted by ingress.
///
/// # Errors
///
/// Returns [`GrpcBoundaryError::MissingContext`] when dispatch bypassed
/// trusted ingress.
pub fn verified_request_context<B>(
    request: &Request<B>,
) -> Result<&VerifiedRequestContext, GrpcBoundaryError> {
    request
        .extensions()
        .get::<VerifiedRequestContext>()
        .ok_or(GrpcBoundaryError::MissingContext)
}

/// Checks one decoded message against stream bounds.
///
/// # Errors
///
/// Returns [`GrpcBoundaryError`] when the message count or size exceeds policy.
pub fn enforce_inbound_message(
    message_index: usize,
    decoded_bytes: usize,
    limits: StreamLimits,
) -> Result<(), GrpcBoundaryError> {
    if message_index >= limits.max_inbound_messages {
        return Err(GrpcBoundaryError::TooManyMessages);
    }
    if decoded_bytes > limits.max_message_bytes {
        return Err(GrpcBoundaryError::MessageTooLarge);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::HeaderMap;
    use http_body_util::{BodyExt, StreamBody};
    use std::convert::Infallible;

    #[test]
    fn service_path_is_classified_as_grpc() {
        let request = Request::builder()
            .uri("/auth.v1.AuthService/Login")
            .body(())
            .expect("valid fixture");

        assert!(is_grpc_request(&request, &["/auth.v1.AuthService/"]));
    }

    #[test]
    fn trailers_only_status_is_promoted_to_response_headers() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("8"));
        trailers.insert(
            "grpc-message",
            HeaderValue::from_static("stream%20limit%20exceeded"),
        );
        let body = StreamBody::new(futures::stream::iter([Ok::<_, Infallible>(
            Frame::<Bytes>::trailers(trailers),
        )]));
        let response = http::Response::builder()
            .status(200)
            .header(CONTENT_TYPE, "application/grpc")
            .body(body)
            .expect("valid fixture");

        let response = normalize_trailers_only_response(response);

        assert_eq!(response.headers()["grpc-status"], "8");
        assert_eq!(
            response.headers()["grpc-message"],
            "stream%20limit%20exceeded"
        );
        let collected = futures::executor::block_on(response.into_body().collect())
            .expect("empty normalized body");
        assert!(collected.to_bytes().is_empty());
    }

    #[test]
    fn empty_data_before_trailers_is_treated_as_trailers_only() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("8"));
        let body = StreamBody::new(futures::stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::new())),
            Ok(Frame::trailers(trailers)),
        ]));
        let response = http::Response::new(body);

        let response = normalize_trailers_only_response(response);

        assert_eq!(response.headers()["grpc-status"], "8");
        assert!(response.body().is_end_stream());
    }

    #[test]
    fn self_woken_trailers_only_status_is_promoted_to_response_headers() {
        let mut yielded = false;
        let body = StreamBody::new(futures::stream::poll_fn(move |context| {
            if !yielded {
                yielded = true;
                context.waker().wake_by_ref();
                return Poll::Pending;
            }

            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("8"));
            Poll::Ready(Some(Ok::<_, Infallible>(Frame::<Bytes>::trailers(
                trailers,
            ))))
        }));
        let response = http::Response::new(body);

        let response = normalize_trailers_only_response(response);

        assert_eq!(response.headers()["grpc-status"], "8");
    }

    #[test]
    fn awaited_trailers_only_status_is_promoted_after_external_wake() {
        let mut yielded = false;
        let body = StreamBody::new(futures::stream::poll_fn(move |context| {
            if !yielded {
                yielded = true;
                context.waker().wake_by_ref();
                return Poll::Pending;
            }

            let mut trailers = HeaderMap::new();
            trailers.insert("grpc-status", HeaderValue::from_static("8"));
            Poll::Ready(Some(Ok::<_, Infallible>(Frame::<Bytes>::trailers(
                trailers,
            ))))
        }));
        let response = http::Response::new(body);

        let response = futures::executor::block_on(
            normalize_trailers_only_response_awaiting_first_frame(response),
        );

        assert_eq!(response.headers()["grpc-status"], "8");
    }

    #[test]
    fn data_first_response_keeps_data_and_trailers_streaming() {
        let mut trailers = HeaderMap::new();
        trailers.insert("grpc-status", HeaderValue::from_static("0"));
        let body = StreamBody::new(futures::stream::iter([
            Ok::<_, Infallible>(Frame::data(Bytes::from_static(b"frame"))),
            Ok(Frame::trailers(trailers)),
        ]));
        let response = http::Response::new(body);

        let response = normalize_trailers_only_response(response);
        let collected = futures::executor::block_on(response.into_body().collect())
            .expect("stream remains valid");

        let grpc_status = collected.trailers().expect("trailers")["grpc-status"]
            .to_str()
            .expect("ASCII status")
            .to_string();
        assert_eq!(collected.to_bytes(), Bytes::from_static(b"frame"));
        assert_eq!(grpc_status, "0");
    }
}
