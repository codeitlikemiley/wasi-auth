//! Bounded native HTTP host for the reference Cedar AuthZEN service.

use std::env;
use std::fmt;
use std::fs;
use std::io::{self, Read as _, Write as _};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::path::Path;
use std::sync::{Arc, Mutex, mpsc};
use std::thread;
use std::time::{Duration, Instant};

use http::header::{AUTHORIZATION, CONTENT_LENGTH, HOST, TRANSFER_ENCODING, WWW_AUTHENTICATE};
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode, Uri};
use wasi_authz_cedar_pdp::CedarPdp;
use wasi_authz_client::BearerToken;
use wasi_authz_contract::MAX_DOCUMENT_BYTES;

const MAX_HEADER_BYTES: usize = 16 * 1024;
const MAX_POLICY_ARTIFACT_BYTES: usize = 4 * 1024 * 1024;
const DEFAULT_READ_TIMEOUT: Duration = Duration::from_secs(5);
const DEFAULT_WRITE_TIMEOUT: Duration = Duration::from_secs(5);

fn main() -> Result<(), MainError> {
    let config = Config::from_environment()?;
    let policy = read_bounded(&config.policy_path)?;
    let schema = read_bounded(&config.schema_path)?;
    let entities = read_bounded(&config.entities_path)?;
    let pdp = Arc::new(
        CedarPdp::new_validated(
            &policy,
            &schema,
            &entities,
            config.policy_revision,
            "cedar-4.11.2",
        )
        .map_err(|_| MainError::PolicyActivation)?,
    );
    let authentication = Arc::new(config.authentication);
    let listener = TcpListener::bind(config.listen).map_err(|_| MainError::Listen)?;
    let (sender, receiver) = mpsc::sync_channel::<TcpStream>(config.workers.saturating_mul(16));
    let receiver = Arc::new(Mutex::new(receiver));
    for _ in 0..config.workers {
        let receiver = Arc::clone(&receiver);
        let pdp = Arc::clone(&pdp);
        let authentication = Arc::clone(&authentication);
        thread::Builder::new()
            .name("cedar-pdp-worker".to_owned())
            .spawn(move || worker_loop(receiver, pdp, authentication))
            .map_err(|_| MainError::Worker)?;
    }
    println!(
        "wasi-authz Cedar PDP listening on {} with {} workers",
        config.listen, config.workers
    );
    for incoming in listener.incoming() {
        let stream = incoming.map_err(|_| MainError::Accept)?;
        sender.send(stream).map_err(|_| MainError::Worker)?;
    }
    Ok(())
}

fn worker_loop(
    receiver: Arc<Mutex<mpsc::Receiver<TcpStream>>>,
    pdp: Arc<CedarPdp>,
    authentication: Arc<PepAuthentication>,
) {
    loop {
        let stream = {
            let Ok(receiver) = receiver.lock() else {
                return;
            };
            let Ok(stream) = receiver.recv() else {
                return;
            };
            stream
        };
        let _ = handle_connection(stream, &pdp, &authentication);
    }
}

fn handle_connection(
    mut stream: TcpStream,
    pdp: &CedarPdp,
    authentication: &PepAuthentication,
) -> io::Result<()> {
    stream.set_nodelay(true)?;
    stream.set_write_timeout(Some(DEFAULT_WRITE_TIMEOUT))?;
    let deadline = Instant::now() + DEFAULT_READ_TIMEOUT;
    let response = match read_request(&mut stream, deadline) {
        Ok(mut request) if authentication.authorizes(request.headers()) => {
            request.headers_mut().remove(AUTHORIZATION);
            pdp.handle(request)
        }
        Ok(_) => unauthorized_response(),
        Err(error) => empty_response(error.status()),
    };
    write_response(&mut stream, response)
}

#[derive(Clone, Copy, Debug)]
enum RequestReadError {
    BadRequest,
    LengthRequired,
    PayloadTooLarge,
}

impl RequestReadError {
    fn status(self) -> StatusCode {
        match self {
            Self::BadRequest => StatusCode::BAD_REQUEST,
            Self::LengthRequired => StatusCode::LENGTH_REQUIRED,
            Self::PayloadTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        }
    }
}

fn read_request(
    stream: &mut TcpStream,
    deadline: Instant,
) -> Result<Request<Vec<u8>>, RequestReadError> {
    let mut buffer = Vec::with_capacity(4 * 1024);
    let header_end = loop {
        if let Some(position) = find_header_end(&buffer) {
            break position;
        }
        if buffer.len() >= MAX_HEADER_BYTES {
            return Err(RequestReadError::PayloadTooLarge);
        }
        let mut chunk = [0_u8; 4 * 1024];
        let count = read_with_deadline(stream, &mut chunk, deadline)?;
        if count == 0 {
            return Err(RequestReadError::BadRequest);
        }
        if buffer.len().saturating_add(count) > MAX_HEADER_BYTES + MAX_DOCUMENT_BYTES {
            return Err(RequestReadError::PayloadTooLarge);
        }
        buffer.extend_from_slice(&chunk[..count]);
    };
    if header_end > MAX_HEADER_BYTES {
        return Err(RequestReadError::PayloadTooLarge);
    }
    let head =
        std::str::from_utf8(&buffer[..header_end]).map_err(|_| RequestReadError::BadRequest)?;
    let mut lines = head.split("\r\n");
    let request_line = lines.next().ok_or(RequestReadError::BadRequest)?;
    let mut request_parts = request_line.split_ascii_whitespace();
    let method = request_parts.next().ok_or(RequestReadError::BadRequest)?;
    let target = request_parts.next().ok_or(RequestReadError::BadRequest)?;
    let version = request_parts.next().ok_or(RequestReadError::BadRequest)?;
    if request_parts.next().is_some() || !matches!(version, "HTTP/1.0" | "HTTP/1.1") {
        return Err(RequestReadError::BadRequest);
    }
    let method = Method::from_bytes(method.as_bytes()).map_err(|_| RequestReadError::BadRequest)?;
    let uri = target
        .parse::<Uri>()
        .map_err(|_| RequestReadError::BadRequest)?;
    if uri.scheme().is_some() || uri.authority().is_some() {
        return Err(RequestReadError::BadRequest);
    }
    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(RequestReadError::BadRequest)?;
        let name =
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| RequestReadError::BadRequest)?;
        let value =
            HeaderValue::from_str(value.trim()).map_err(|_| RequestReadError::BadRequest)?;
        headers.append(name, value);
    }
    if headers.contains_key(TRANSFER_ENCODING) || !has_single_header(&headers, HOST) {
        return Err(RequestReadError::BadRequest);
    }
    let content_length = single_content_length(&headers)?;
    if content_length > MAX_DOCUMENT_BYTES {
        return Err(RequestReadError::PayloadTooLarge);
    }
    let body_start = header_end + 4;
    let expected_total = body_start.saturating_add(content_length);
    while buffer.len() < expected_total {
        let remaining = expected_total - buffer.len();
        let mut chunk = [0_u8; 4 * 1024];
        let read_length = remaining.min(chunk.len());
        let count = read_with_deadline(stream, &mut chunk[..read_length], deadline)?;
        if count == 0 {
            return Err(RequestReadError::BadRequest);
        }
        buffer.extend_from_slice(&chunk[..count]);
    }
    if buffer.len() != expected_total {
        return Err(RequestReadError::BadRequest);
    }
    let mut request = Request::new(buffer[body_start..].to_vec());
    *request.method_mut() = method;
    *request.uri_mut() = uri;
    *request.headers_mut() = headers;
    Ok(request)
}

fn read_with_deadline(
    stream: &mut TcpStream,
    buffer: &mut [u8],
    deadline: Instant,
) -> Result<usize, RequestReadError> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(RequestReadError::BadRequest);
    }
    stream
        .set_read_timeout(Some(remaining))
        .map_err(|_| RequestReadError::BadRequest)?;
    stream
        .read(buffer)
        .map_err(|_| RequestReadError::BadRequest)
}

fn find_header_end(buffer: &[u8]) -> Option<usize> {
    buffer.windows(4).position(|window| window == b"\r\n\r\n")
}

fn has_single_header(headers: &HeaderMap, name: HeaderName) -> bool {
    let mut values = headers.get_all(name).iter();
    values.next().is_some() && values.next().is_none()
}

fn single_content_length(headers: &HeaderMap) -> Result<usize, RequestReadError> {
    let mut values = headers.get_all(CONTENT_LENGTH).iter();
    let value = values.next().ok_or(RequestReadError::LengthRequired)?;
    if values.next().is_some() {
        return Err(RequestReadError::BadRequest);
    }
    value
        .to_str()
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .ok_or(RequestReadError::BadRequest)
}

fn write_response(stream: &mut TcpStream, response: Response<Vec<u8>>) -> io::Result<()> {
    let status = response.status();
    let reason = status.canonical_reason().unwrap_or("Unknown");
    write!(stream, "HTTP/1.1 {} {}\r\n", status.as_u16(), reason)?;
    for (name, value) in response.headers() {
        stream.write_all(name.as_str().as_bytes())?;
        stream.write_all(b": ")?;
        stream.write_all(value.as_bytes())?;
        stream.write_all(b"\r\n")?;
    }
    stream.write_all(b"connection: close\r\n\r\n")?;
    stream.write_all(response.body())?;
    stream.flush()
}

fn empty_response(status: StatusCode) -> Response<Vec<u8>> {
    let mut response = Response::new(Vec::new());
    *response.status_mut() = status;
    response
        .headers_mut()
        .insert(CONTENT_LENGTH, HeaderValue::from_static("0"));
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response
}

fn unauthorized_response() -> Response<Vec<u8>> {
    let mut response = empty_response(StatusCode::UNAUTHORIZED);
    response
        .headers_mut()
        .insert(WWW_AUTHENTICATE, HeaderValue::from_static("Bearer"));
    response
}

enum PepAuthentication {
    Bearer(BearerToken),
    UnauthenticatedLoopbackDevelopment,
}

impl PepAuthentication {
    fn from_environment(listen: SocketAddr) -> Result<Self, MainError> {
        if let Ok(token) = env::var("WASI_AUTHZ_PDP_BEARER_TOKEN") {
            return Ok(Self::Bearer(
                BearerToken::new(token).map_err(|_| MainError::Configuration)?,
            ));
        }
        let development = env::var("WASI_AUTHZ_PDP_ALLOW_UNAUTHENTICATED_LOOPBACK_DEV")
            .ok()
            .is_some_and(|value| value == "true");
        if listen.ip().is_loopback() && development {
            Ok(Self::UnauthenticatedLoopbackDevelopment)
        } else {
            Err(MainError::PdpAuthenticationRequired)
        }
    }

    fn authorizes(&self, headers: &HeaderMap) -> bool {
        match self {
            Self::UnauthenticatedLoopbackDevelopment => true,
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

struct Config {
    listen: SocketAddr,
    policy_path: String,
    schema_path: String,
    entities_path: String,
    policy_revision: String,
    workers: usize,
    authentication: PepAuthentication,
}

impl Config {
    fn from_environment() -> Result<Self, MainError> {
        let listen = env::var("WASI_AUTHZ_CEDAR_LISTEN")
            .unwrap_or_else(|_| "127.0.0.1:8787".to_owned())
            .parse::<SocketAddr>()
            .map_err(|_| MainError::Configuration)?;
        if !listen.ip().is_loopback() {
            return Err(MainError::LoopbackOnly);
        }
        let workers = env::var("WASI_AUTHZ_CEDAR_WORKERS")
            .ok()
            .map(|value| value.parse::<usize>())
            .transpose()
            .map_err(|_| MainError::Configuration)?
            .unwrap_or_else(|| {
                thread::available_parallelism()
                    .map_or(4, usize::from)
                    .clamp(1, 16)
            });
        if !(1..=64).contains(&workers) {
            return Err(MainError::Configuration);
        }
        let authentication = PepAuthentication::from_environment(listen)?;
        Ok(Self {
            listen,
            policy_path: required_env("WASI_AUTHZ_CEDAR_POLICY_PATH")?,
            schema_path: required_env("WASI_AUTHZ_CEDAR_SCHEMA_PATH")?,
            entities_path: required_env("WASI_AUTHZ_CEDAR_ENTITIES_PATH")?,
            policy_revision: required_env("WASI_AUTHZ_CEDAR_POLICY_REVISION")?,
            workers,
            authentication,
        })
    }
}

fn required_env(name: &'static str) -> Result<String, MainError> {
    env::var(name).map_err(|_| MainError::MissingEnvironment(name))
}

fn read_bounded(path: &str) -> Result<String, MainError> {
    let metadata = fs::metadata(Path::new(path)).map_err(|_| MainError::PolicyArtifact)?;
    if metadata.len() > MAX_POLICY_ARTIFACT_BYTES as u64 {
        return Err(MainError::PolicyArtifact);
    }
    fs::read_to_string(Path::new(path)).map_err(|_| MainError::PolicyArtifact)
}

#[derive(Debug)]
enum MainError {
    MissingEnvironment(&'static str),
    Configuration,
    LoopbackOnly,
    PolicyArtifact,
    PolicyActivation,
    PdpAuthenticationRequired,
    Listen,
    Accept,
    Worker,
}

impl fmt::Display for MainError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MissingEnvironment(name) => write!(formatter, "missing environment: {name}"),
            Self::Configuration => formatter.write_str("invalid Cedar PDP configuration"),
            Self::LoopbackOnly => formatter.write_str(
                "the native Cedar PDP is loopback-only; use an authenticated TLS ingress sidecar",
            ),
            Self::PolicyArtifact => formatter.write_str("failed to load bounded policy artifact"),
            Self::PolicyActivation => formatter.write_str("Cedar policy activation failed"),
            Self::PdpAuthenticationRequired => formatter
                .write_str("PDP authentication is required outside explicit loopback development"),
            Self::Listen => formatter.write_str("Cedar PDP listener failed"),
            Self::Accept => formatter.write_str("Cedar PDP connection acceptance failed"),
            Self::Worker => formatter.write_str("Cedar PDP worker pool failed"),
        }
    }
}

impl std::error::Error for MainError {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn duplicate_length_and_transfer_encoding_are_rejected_by_helpers() {
        let mut headers = HeaderMap::new();
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("1"));
        headers.append(CONTENT_LENGTH, HeaderValue::from_static("1"));
        assert!(matches!(
            single_content_length(&headers),
            Err(RequestReadError::BadRequest)
        ));

        let mut chunked = HeaderMap::new();
        chunked.insert(TRANSFER_ENCODING, HeaderValue::from_static("chunked"));
        assert!(chunked.contains_key(TRANSFER_ENCODING));
    }

    #[test]
    fn bearer_authentication_is_exact_and_duplicate_safe() {
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

    #[test]
    fn response_writer_never_uses_request_data() {
        let response = empty_response(StatusCode::BAD_REQUEST);
        let mut output = Cursor::new(Vec::new());

        write_response_cursor(&mut output, response).expect("response writes");

        let output = String::from_utf8(output.into_inner()).expect("HTTP is UTF-8");
        assert!(output.starts_with("HTTP/1.1 400 Bad Request\r\n"));
        assert!(output.ends_with("connection: close\r\n\r\n"));
    }

    fn write_response_cursor(
        output: &mut Cursor<Vec<u8>>,
        response: Response<Vec<u8>>,
    ) -> io::Result<()> {
        let status = response.status();
        let reason = status.canonical_reason().unwrap_or("Unknown");
        write!(output, "HTTP/1.1 {} {}\r\n", status.as_u16(), reason)?;
        for (name, value) in response.headers() {
            output.write_all(name.as_str().as_bytes())?;
            output.write_all(b": ")?;
            output.write_all(value.as_bytes())?;
            output.write_all(b"\r\n")?;
        }
        output.write_all(b"connection: close\r\n\r\n")?;
        output.write_all(response.body())
    }
}
