//! WASIp2 `wasi:http/outgoing-handler` transport.
//!
//! WASIp2 pollables are not Rust futures. The transport therefore requires an
//! explicit [`PollableWaiter`] supplied by the embedding async runtime. This
//! keeps the client framework-neutral while ensuring it never hides a blocking
//! `pollable.block`, `std::io::Read`, or `std::io::Write` loop inside an async
//! future.

use std::future::Future;
use std::pin::Pin;

#[cfg(any(target_arch = "wasm32", test))]
use futures::future::{Either, select};
use http::Request;
#[cfg(target_arch = "wasm32")]
use http::Response;
use thiserror::Error;
use wasi::io::poll::Pollable;

use crate::{
    DEFAULT_TIMEOUT_NANOS, HttpTransport, TransportConfigError, TransportError, TransportFuture,
    timeout_nanos,
};

/// Boxed future used to await one WASIp2 pollable.
pub type PollableWaitFuture<'a> =
    Pin<Box<dyn Future<Output = Result<(), PollableWaitError>> + Send + 'a>>;

/// Async-runtime adapter for WASIp2 pollables.
///
/// Implementations must register the pollable with their existing event loop,
/// return `Pending` rather than block the guest thread, and remove/drop the
/// registration when the returned future is dropped. The transport invokes
/// this method concurrently for an I/O pollable and one absolute-deadline
/// pollable; dropping either future must therefore be cancellation-safe.
///
/// With `leptos_wasi`, adapt its cancellation-safe waiter without introducing
/// a dependency from this framework-neutral crate:
///
/// ```ignore
/// use leptos_wasi::ExecutorError;
/// use wasi::io::poll::Pollable;
/// use wasi_authz_client::wasip2::{
///     PollableWaitError, PollableWaitFuture, PollableWaiter,
///     Wasip2Transport,
/// };
///
/// #[derive(Clone, Copy, Debug)]
/// struct LeptosPollableWaiter;
///
/// impl PollableWaiter for LeptosPollableWaiter {
///     fn wait<'a>(&'a self, pollable: Pollable) -> PollableWaitFuture<'a> {
///         Box::pin(async move {
///             leptos_wasi::wasip2::WaitPoll::new(pollable)
///                 .await
///                 .map_err(|error| match error {
///                     ExecutorError::PollableCanceled
///                     | ExecutorError::RunUntilCanceled => {
///                         PollableWaitError::Canceled
///                     }
///                     _ => PollableWaitError::Unavailable,
///                 })
///         })
///     }
/// }
///
/// let transport = Wasip2Transport::new(LeptosPollableWaiter);
/// ```
pub trait PollableWaiter: Send + Sync {
    /// Waits asynchronously for one pollable to become ready.
    fn wait<'a>(&'a self, pollable: Pollable) -> PollableWaitFuture<'a>;
}

/// Failure reported by a WASIp2 async-runtime pollable adapter.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum PollableWaitError {
    /// The owning task or request canceled the pollable registration.
    #[error("WASIp2 pollable wait was canceled")]
    Canceled,
    /// The runtime could not register or drive the pollable.
    #[error("WASIp2 pollable waiter is unavailable")]
    Unavailable,
}

/// WASIp2 outbound HTTP transport supplied by the component host.
///
/// There is deliberately no zero-argument constructor or blocking default.
/// Callers must inject the same cancellation-safe pollable waiter used by the
/// component's async executor.
#[derive(Clone, Copy, Debug)]
pub struct Wasip2Transport<W> {
    timeout_nanos: u64,
    waiter: W,
}

impl<W> Wasip2Transport<W> {
    /// Constructs a transport with a two-second absolute deadline.
    pub fn new(waiter: W) -> Self {
        Self {
            timeout_nanos: DEFAULT_TIMEOUT_NANOS,
            waiter,
        }
    }

    /// Sets one absolute deadline for request upload, response headers, and
    /// response body collection.
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

impl<W> HttpTransport for Wasip2Transport<W>
where
    W: PollableWaiter,
{
    fn send<'a>(&'a self, request: Request<Vec<u8>>) -> TransportFuture<'a> {
        #[cfg(target_arch = "wasm32")]
        {
            Box::pin(send_request(request, self.timeout_nanos, &self.waiter))
        }
        #[cfg(not(target_arch = "wasm32"))]
        {
            let _ = (&self.waiter, self.timeout_nanos, request);
            Box::pin(async { Err(TransportError::UnsupportedTarget) })
        }
    }
}

#[cfg(any(target_arch = "wasm32", test))]
fn map_wait_error(error: PollableWaitError) -> TransportError {
    match error {
        PollableWaitError::Canceled => TransportError::Canceled,
        PollableWaitError::Unavailable => TransportError::Unavailable,
    }
}

#[cfg(any(target_arch = "wasm32", test))]
async fn race_with_deadline<Operation, Deadline, Now>(
    operation: Operation,
    deadline_wait: Deadline,
    deadline: u64,
    now: Now,
) -> Result<(), TransportError>
where
    Operation: Future<Output = Result<(), PollableWaitError>> + Unpin,
    Deadline: Future<Output = Result<(), PollableWaitError>> + Unpin,
    Now: Fn() -> u64,
{
    if now() >= deadline {
        return Err(TransportError::Timeout);
    }

    match select(operation, deadline_wait).await {
        Either::Left((operation_result, losing_deadline)) => {
            drop(losing_deadline);
            if now() >= deadline {
                Err(TransportError::Timeout)
            } else {
                operation_result.map_err(map_wait_error)
            }
        }
        Either::Right((deadline_result, losing_operation)) => {
            drop(losing_operation);
            match deadline_result {
                Ok(()) => Err(TransportError::Timeout),
                Err(error) => Err(map_wait_error(error)),
            }
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
fn checked_deadline(now: u64, timeout_nanos: u64) -> Result<u64, TransportError> {
    now.checked_add(timeout_nanos)
        .ok_or(TransportError::Timeout)
}

#[cfg(any(target_arch = "wasm32", test))]
fn checked_remaining(deadline: u64, now: u64) -> Result<u64, TransportError> {
    deadline
        .checked_sub(now)
        .filter(|remaining| *remaining != 0)
        .ok_or(TransportError::Timeout)
}

#[cfg(target_arch = "wasm32")]
fn deadline_after(timeout_nanos: u64) -> Result<u64, TransportError> {
    checked_deadline(wasi::clocks::monotonic_clock::now(), timeout_nanos)
}

#[cfg(target_arch = "wasm32")]
fn remaining_until(deadline: u64) -> Result<u64, TransportError> {
    checked_remaining(deadline, wasi::clocks::monotonic_clock::now())
}

#[cfg(target_arch = "wasm32")]
async fn wait_until<W>(waiter: &W, pollable: Pollable, deadline: u64) -> Result<(), TransportError>
where
    W: PollableWaiter + ?Sized,
{
    let _ = remaining_until(deadline)?;
    let deadline_pollable = wasi::clocks::monotonic_clock::subscribe_instant(deadline);
    race_with_deadline(
        waiter.wait(pollable),
        waiter.wait(deadline_pollable),
        deadline,
        wasi::clocks::monotonic_clock::now,
    )
    .await
}

#[cfg(target_arch = "wasm32")]
async fn send_request<W>(
    request: Request<Vec<u8>>,
    timeout_nanos: u64,
    waiter: &W,
) -> Result<Response<Vec<u8>>, TransportError>
where
    W: PollableWaiter + ?Sized,
{
    use wasi::http::outgoing_handler;
    use wasi::http::types::{
        Fields, IncomingBody, OutgoingBody, OutgoingRequest, RequestOptions, Scheme,
    };

    let deadline = deadline_after(timeout_nanos)?;
    let (parts, body) = request.into_parts();
    let headers = parts
        .headers
        .iter()
        .map(|(name, value)| (name.as_str().to_owned(), value.as_bytes().to_vec()))
        .collect::<Vec<_>>();
    let fields = Fields::from_list(&headers).map_err(|_| TransportError::Protocol)?;
    let outgoing = OutgoingRequest::new(fields);
    let method = method_to_wasi(&parts.method);
    outgoing
        .set_method(&method)
        .map_err(|()| TransportError::Protocol)?;
    let scheme = match parts.uri.scheme_str() {
        Some("http") => Scheme::Http,
        Some("https") => Scheme::Https,
        _ => return Err(TransportError::Protocol),
    };
    outgoing
        .set_scheme(Some(&scheme))
        .map_err(|()| TransportError::Protocol)?;
    outgoing
        .set_authority(parts.uri.authority().map(http::uri::Authority::as_str))
        .map_err(|()| TransportError::Protocol)?;
    outgoing
        .set_path_with_query(
            parts
                .uri
                .path_and_query()
                .map(http::uri::PathAndQuery::as_str),
        )
        .map_err(|()| TransportError::Protocol)?;

    let outgoing_body = outgoing.body().map_err(|()| TransportError::Protocol)?;
    let output = outgoing_body
        .write()
        .map_err(|()| TransportError::Protocol)?;
    let upload = write_request_body(&output, &body, deadline, waiter).await;
    drop(output);
    if let Err(error) = upload {
        drop(outgoing_body);
        return Err(error);
    }
    drop(body);
    OutgoingBody::finish(outgoing_body, None).map_err(map_error_code)?;

    let remaining = remaining_until(deadline)?;
    let options = RequestOptions::new();
    options
        .set_connect_timeout(Some(remaining))
        .map_err(|()| TransportError::Protocol)?;
    options
        .set_first_byte_timeout(Some(remaining))
        .map_err(|()| TransportError::Protocol)?;
    options
        .set_between_bytes_timeout(Some(remaining))
        .map_err(|()| TransportError::Protocol)?;
    let pending = outgoing_handler::handle(outgoing, Some(options)).map_err(map_error_code)?;
    wait_until(waiter, pending.subscribe(), deadline).await?;
    let incoming = pending
        .get()
        .ok_or(TransportError::Protocol)?
        .map_err(|()| TransportError::Protocol)?
        .map_err(map_error_code)?;
    drop(pending);

    let status = incoming.status();
    let headers_resource = incoming.headers();
    let headers = headers_resource.entries();
    drop(headers_resource);
    let content_length = declared_content_length(&headers)?;
    let incoming_body = incoming.consume().map_err(|()| TransportError::Protocol)?;
    let stream = incoming_body
        .stream()
        .map_err(|()| TransportError::Protocol)?;
    let collected = collect_response_body(&stream, deadline, waiter).await;
    drop(stream);
    let collected = match collected {
        Ok(collected) => {
            let trailers = IncomingBody::finish(incoming_body);
            drop(trailers);
            collected
        }
        Err(error) => {
            drop(incoming_body);
            return Err(error);
        }
    };
    if content_length.is_some_and(|declared| declared != collected.len()) {
        return Err(TransportError::Protocol);
    }

    let mut builder = Response::builder().status(status);
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    builder
        .body(collected)
        .map_err(|_| TransportError::Protocol)
}

#[cfg(target_arch = "wasm32")]
async fn write_request_body<W>(
    output: &wasi::io::streams::OutputStream,
    mut bytes: &[u8],
    deadline: u64,
    waiter: &W,
) -> Result<(), TransportError>
where
    W: PollableWaiter + ?Sized,
{
    while !bytes.is_empty() {
        let _ = remaining_until(deadline)?;
        let capacity = output.check_write().map_err(map_stream_error)?;
        if capacity == 0 {
            wait_until(waiter, output.subscribe(), deadline).await?;
            continue;
        }
        let count = usize::try_from(capacity)
            .unwrap_or(usize::MAX)
            .min(bytes.len());
        output.write(&bytes[..count]).map_err(map_stream_error)?;
        bytes = &bytes[count..];
    }
    let _ = remaining_until(deadline)?;
    output.flush().map_err(map_stream_error)?;
    wait_until(waiter, output.subscribe(), deadline).await
}

#[cfg(target_arch = "wasm32")]
async fn collect_response_body<W>(
    stream: &wasi::io::streams::InputStream,
    deadline: u64,
    waiter: &W,
) -> Result<Vec<u8>, TransportError>
where
    W: PollableWaiter + ?Sized,
{
    use wasi::io::streams::StreamError;
    use wasi_authz_contract::MAX_DOCUMENT_BYTES;

    const READ_CHUNK_BYTES: usize = 8 * 1024;

    let mut collected = Vec::new();
    loop {
        let _ = remaining_until(deadline)?;
        let remaining = (MAX_DOCUMENT_BYTES + 1).saturating_sub(collected.len());
        let requested = remaining.min(READ_CHUNK_BYTES);
        match stream.read(requested as u64) {
            Ok(bytes) if bytes.is_empty() => {
                wait_until(waiter, stream.subscribe(), deadline).await?;
            }
            Ok(bytes) => {
                if bytes.len() > requested
                    || collected.len().saturating_add(bytes.len()) > MAX_DOCUMENT_BYTES
                {
                    return Err(TransportError::ResponseTooLarge);
                }
                collected.extend_from_slice(&bytes);
            }
            Err(StreamError::Closed) => {
                let _ = remaining_until(deadline)?;
                return Ok(collected);
            }
            Err(StreamError::LastOperationFailed(_)) => {
                return Err(TransportError::Unavailable);
            }
        }
    }
}

#[cfg(target_arch = "wasm32")]
fn method_to_wasi(method: &http::Method) -> wasi::http::types::Method {
    use wasi::http::types::Method;

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
fn map_stream_error(error: wasi::io::streams::StreamError) -> TransportError {
    let _ = error;
    TransportError::Unavailable
}

#[cfg(target_arch = "wasm32")]
fn map_error_code(error: wasi::http::types::ErrorCode) -> TransportError {
    use wasi::http::types::ErrorCode;

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
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use std::task::{Context, Poll};

    use futures::executor::block_on;
    use futures::future::{pending, ready};

    use super::*;

    #[derive(Clone, Copy, Debug)]
    struct UnavailableWaiter;

    impl PollableWaiter for UnavailableWaiter {
        fn wait<'a>(&'a self, _pollable: Pollable) -> PollableWaitFuture<'a> {
            Box::pin(async { Err(PollableWaitError::Unavailable) })
        }
    }

    struct DropProbe<F> {
        future: F,
        dropped: Arc<AtomicBool>,
    }

    impl<F> DropProbe<F> {
        fn new(future: F, dropped: Arc<AtomicBool>) -> Self {
            Self { future, dropped }
        }
    }

    impl<F> Future for DropProbe<F>
    where
        F: Future + Unpin,
    {
        type Output = F::Output;

        fn poll(mut self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<Self::Output> {
            Pin::new(&mut self.future).poll(context)
        }
    }

    impl<F> Drop for DropProbe<F> {
        fn drop(&mut self) {
            self.dropped.store(true, Ordering::SeqCst);
        }
    }

    #[test]
    #[cfg(not(target_arch = "wasm32"))]
    fn native_target_fails_explicitly() {
        let request = Request::builder()
            .uri("https://pdp.example/access/v1/evaluation")
            .body(Vec::new())
            .expect("request builds");

        let result = block_on(Wasip2Transport::new(UnavailableWaiter).send(request));

        assert!(matches!(result, Err(TransportError::UnsupportedTarget)));
    }

    #[test]
    fn operation_completion_drops_the_losing_deadline_wait() {
        let deadline_dropped = Arc::new(AtomicBool::new(false));
        let result = block_on(race_with_deadline(
            ready(Ok(())),
            DropProbe::new(
                pending::<Result<(), PollableWaitError>>(),
                deadline_dropped.clone(),
            ),
            10,
            || 1,
        ));

        assert_eq!(result, Ok(()));
        assert!(deadline_dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn deadline_completion_drops_the_losing_operation_wait() {
        let operation_dropped = Arc::new(AtomicBool::new(false));
        let result = block_on(race_with_deadline(
            DropProbe::new(
                pending::<Result<(), PollableWaitError>>(),
                operation_dropped.clone(),
            ),
            ready(Ok(())),
            10,
            || 1,
        ));

        assert_eq!(result, Err(TransportError::Timeout));
        assert!(operation_dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn dropping_the_race_cancels_both_pollable_waits() {
        let operation_dropped = Arc::new(AtomicBool::new(false));
        let deadline_dropped = Arc::new(AtomicBool::new(false));
        let mut race = Box::pin(race_with_deadline(
            DropProbe::new(
                pending::<Result<(), PollableWaitError>>(),
                operation_dropped.clone(),
            ),
            DropProbe::new(
                pending::<Result<(), PollableWaitError>>(),
                deadline_dropped.clone(),
            ),
            10,
            || 1,
        ));
        let waker = std::task::Waker::noop();
        let mut context = Context::from_waker(waker);

        assert!(race.as_mut().poll(&mut context).is_pending());
        drop(race);

        assert!(operation_dropped.load(Ordering::SeqCst));
        assert!(deadline_dropped.load(Ordering::SeqCst));
    }

    #[test]
    fn cancellation_remains_distinct_from_provider_unavailability() {
        let result = block_on(race_with_deadline(
            ready(Err(PollableWaitError::Canceled)),
            pending::<Result<(), PollableWaitError>>(),
            10,
            || 1,
        ));

        assert_eq!(result, Err(TransportError::Canceled));
    }

    #[test]
    fn absolute_deadline_wins_even_when_the_operation_is_ready() {
        let calls = std::cell::Cell::new(0_u8);
        let result = block_on(race_with_deadline(
            ready(Ok(())),
            pending::<Result<(), PollableWaitError>>(),
            10,
            || {
                let call = calls.get();
                calls.set(call.saturating_add(1));
                if call == 0 { 9 } else { 10 }
            },
        ));

        assert_eq!(result, Err(TransportError::Timeout));
    }

    #[test]
    fn deadline_arithmetic_is_checked_and_excludes_expiry() {
        assert_eq!(checked_deadline(10, 5), Ok(15));
        assert_eq!(checked_deadline(u64::MAX, 1), Err(TransportError::Timeout));
        assert_eq!(checked_remaining(15, 10), Ok(5));
        assert_eq!(checked_remaining(15, 15), Err(TransportError::Timeout));
        assert_eq!(checked_remaining(15, 16), Err(TransportError::Timeout));
    }

    #[test]
    fn content_length_is_single_strict_and_bounded() {
        assert_eq!(
            declared_content_length(&[("content-length".to_owned(), b" 42 ".to_vec())]),
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
            declared_content_length(&[("content-length".to_owned(), b"4, 4".to_vec())]),
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
    }
}
