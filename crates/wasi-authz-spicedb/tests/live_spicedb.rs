//! Live SpiceDB 1.54 adapter matrix.

use std::env;
use std::fmt;
use std::io::{Read as _, Write as _};
use std::net::{TcpStream, ToSocketAddrs as _};
use std::process::{Command, Stdio};
use std::time::Duration;

use http::header::{AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE, HOST};
use http::{HeaderMap, HeaderName, HeaderValue, Request, Response, StatusCode};
use wasi_authz_client::{
    DecisionProvider as _, HttpTransport, ProviderCapability, TransportError, TransportFuture,
};
use wasi_authz_contract::{
    AccessEvaluation, Action, AuthenticatedSubjectV1, ConsistencyRequirementV1, ContextV1,
    EntityIdV1, EntityTypeV1, IssuerV1, MAX_DOCUMENT_BYTES, Resource, SubjectV1,
};
use wasi_authz_spicedb::{PermissionMap, SpiceDbEndpoint, SpiceDbError, SpiceDbProvider};

const ISSUER: &str = "https://identity.example";

#[test]
#[ignore = "requires scripts/test-spicedb-live.sh"]
fn live_spicedb_matrix() {
    let http_endpoint = required_env("WASI_AUTHZ_SPICEDB_HTTP_ENDPOINT");
    let grpc_endpoint = required_env("WASI_AUTHZ_SPICEDB_GRPC_ENDPOINT");
    let token = required_env("WASI_AUTHZ_SPICEDB_TOKEN");
    let zed = required_env("WASI_AUTHZ_ZED");
    let endpoint = SpiceDbEndpoint::new_loopback_for_dev(&http_endpoint)
        .expect("script supplies a loopback endpoint");
    let transport = LoopbackTransport::new(&http_endpoint, &token);
    let provider = SpiceDbProvider::new(
        endpoint,
        transport,
        PermissionMap::new([
            ("document.view", "view"),
            ("document.edit", "edit"),
            ("document.delete", "delete"),
            ("folder.view", "view"),
        ])
        .expect("valid permission map"),
        "live-schema-1",
        "spicedb-1.54.0",
    )
    .expect("valid live provider");

    for required in [
        ProviderCapability::RelationshipHierarchy,
        ProviderCapability::MinimizeLatencyConsistency,
        ProviderCapability::AtLeastAsFreshConsistency,
        ProviderCapability::FullyConsistentConsistency,
    ] {
        assert!(provider.capabilities().contains(&required));
    }

    assert_allowed(
        &provider,
        evaluation("alice", "document.view", "document", "report-1"),
    );
    assert_allowed(
        &provider,
        evaluation("alice", "document.delete", "document", "report-1"),
    );
    assert_allowed(
        &provider,
        evaluation("bob", "document.edit", "document", "report-1"),
    );
    assert_denied(
        &provider,
        evaluation("bob", "document.delete", "document", "report-1"),
    );
    assert_allowed(
        &provider,
        evaluation("carol", "document.view", "document", "report-1"),
    );
    assert_denied(
        &provider,
        evaluation("carol", "document.edit", "document", "report-1"),
    );
    assert_allowed(
        &provider,
        evaluation("dave", "document.edit", "document", "report-1"),
    );
    assert_allowed(
        &provider,
        evaluation("frank", "document.view", "document", "report-1"),
    );
    assert_denied(
        &provider,
        evaluation("frank", "document.edit", "document", "report-1"),
    );
    assert_denied(
        &provider,
        evaluation("erin", "document.view", "document", "report-1"),
    );
    assert_allowed(
        &provider,
        evaluation("erin", "document.view", "document", "globex-report"),
    );
    assert_denied(
        &provider,
        evaluation("alice", "document.view", "document", "globex-report"),
    );

    let minimize = evaluate_ok(
        &provider,
        evaluation("alice", "document.view", "document", "report-1"),
    );
    assert!(minimize.metadata().consistency_token().is_some());
    let fully_consistent = evaluate_ok(
        &provider,
        with_full_consistency(evaluation("alice", "document.view", "document", "report-1")),
    );
    assert!(fully_consistent.is_allowed());
    let token_value = fully_consistent
        .metadata()
        .consistency_token()
        .expect("SpiceDB returns a checkedAt token")
        .clone();
    let at_least = evaluation("alice", "document.view", "document", "report-1").with_context(
        ContextV1::new()
            .with_consistency(ConsistencyRequirementV1::AtLeastAsFresh { token: token_value }),
    );
    assert_allowed(&provider, at_least);

    mutate_relationship(
        &zed,
        &grpc_endpoint,
        &token,
        "create",
        "document:report-1",
        "editor",
        &format!("user:{}", canonical_id("carol")),
    );
    assert_allowed(
        &provider,
        evaluation("carol", "document.edit", "document", "report-1"),
    );
    mutate_relationship(
        &zed,
        &grpc_endpoint,
        &token,
        "delete",
        "document:report-1",
        "editor",
        &format!("user:{}", canonical_id("carol")),
    );
    assert_denied(
        &provider,
        evaluation("carol", "document.edit", "document", "report-1"),
    );

    let cycle = with_full_consistency(evaluation("alice", "folder.view", "folder", "cycle-a"));
    match block_on(provider.evaluate(&cycle)) {
        Ok(decision) => assert!(
            !decision.is_allowed(),
            "a relationship cycle granted access"
        ),
        Err(SpiceDbError::ProviderUnavailable) => {}
        Err(error) => panic!("unexpected cycle outcome: {error}"),
    }
}

fn evaluation(
    subject_id: &str,
    action: &str,
    resource_type: &str,
    resource_id: &str,
) -> AccessEvaluation {
    let subject = AuthenticatedSubjectV1::new(
        EntityTypeV1::new("user").expect("valid fixture"),
        EntityIdV1::new(subject_id).expect("valid fixture"),
        IssuerV1::new(ISSUER).expect("valid fixture"),
    );
    AccessEvaluation::new(
        SubjectV1::Authenticated(subject),
        Action::new(action).expect("valid fixture"),
        Resource::new(resource_type, resource_id).expect("valid fixture"),
    )
}

fn assert_allowed(provider: &SpiceDbProvider<LoopbackTransport>, request: AccessEvaluation) {
    assert!(evaluate_ok(provider, with_full_consistency(request)).is_allowed());
}

fn assert_denied(provider: &SpiceDbProvider<LoopbackTransport>, request: AccessEvaluation) {
    assert!(!evaluate_ok(provider, with_full_consistency(request)).is_allowed());
}

fn with_full_consistency(request: AccessEvaluation) -> AccessEvaluation {
    request
        .with_context(ContextV1::new().with_consistency(ConsistencyRequirementV1::FullyConsistent))
}

fn evaluate_ok(
    provider: &SpiceDbProvider<LoopbackTransport>,
    request: AccessEvaluation,
) -> wasi_authz_contract::DecisionResponseV1 {
    block_on(provider.evaluate(&request)).expect("live SpiceDB evaluates")
}

fn mutate_relationship(
    zed: &str,
    endpoint: &str,
    token: &str,
    operation: &str,
    resource: &str,
    relation: &str,
    subject: &str,
) {
    let status = Command::new(zed)
        .args([
            "--endpoint",
            endpoint,
            "--token",
            token,
            "--insecure",
            "--skip-version-check",
            "relationship",
            operation,
            resource,
            relation,
            subject,
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .expect("zed runs");
    assert!(status.success(), "zed relationship mutation failed");
}

fn required_env(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| panic!("{name} must be supplied by the live test script"))
}

fn canonical_id(subject: &str) -> String {
    let evaluation = evaluation(subject, "document.view", "document", "report-1");
    let SubjectV1::Authenticated(subject) = evaluation.subject() else {
        panic!("fixture must be authenticated");
    };
    wasi_authz_spicedb::canonical_subject_id(subject)
}

#[derive(Clone)]
struct LoopbackTransport {
    address: String,
    authority: String,
    token: String,
}

impl fmt::Debug for LoopbackTransport {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("LoopbackTransport")
            .field("address", &self.address)
            .field("authority", &self.authority)
            .field("token", &"[REDACTED]")
            .finish()
    }
}

impl LoopbackTransport {
    fn new(endpoint: &str, token: &str) -> Self {
        let uri = endpoint.parse::<http::Uri>().expect("valid fixture URI");
        let authority = uri
            .authority()
            .expect("URI has authority")
            .as_str()
            .to_owned();
        Self {
            address: authority.clone(),
            authority,
            token: token.to_owned(),
        }
    }

    fn send_blocking(
        &self,
        request: Request<Vec<u8>>,
    ) -> Result<Response<Vec<u8>>, TransportError> {
        let address = self
            .address
            .to_socket_addrs()
            .map_err(|_| TransportError::Unavailable)?
            .next()
            .ok_or(TransportError::Unavailable)?;
        let mut stream = TcpStream::connect_timeout(&address, Duration::from_secs(2))
            .map_err(|_| TransportError::Unavailable)?;
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| TransportError::Unavailable)?;
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .map_err(|_| TransportError::Unavailable)?;
        let mut headers = request.headers().clone();
        headers.insert(
            HOST,
            HeaderValue::from_str(&self.authority).map_err(|_| TransportError::Protocol)?,
        );
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", self.token))
                .map_err(|_| TransportError::Protocol)?,
        );
        headers.insert(
            CONTENT_LENGTH,
            HeaderValue::from_str(&request.body().len().to_string())
                .map_err(|_| TransportError::Protocol)?,
        );
        let mut wire = format!("POST {} HTTP/1.1\r\n", request.uri().path()).into_bytes();
        for (name, value) in &headers {
            wire.extend_from_slice(name.as_str().as_bytes());
            wire.extend_from_slice(b": ");
            wire.extend_from_slice(value.as_bytes());
            wire.extend_from_slice(b"\r\n");
        }
        wire.extend_from_slice(b"Connection: close\r\n\r\n");
        wire.extend_from_slice(request.body());
        stream
            .write_all(&wire)
            .map_err(|_| TransportError::Unavailable)?;
        let maximum_wire_bytes = MAX_DOCUMENT_BYTES.saturating_mul(2);
        let mut response = Vec::new();
        stream
            .take((maximum_wire_bytes + 1) as u64)
            .read_to_end(&mut response)
            .map_err(|_| TransportError::Unavailable)?;
        if response.len() > maximum_wire_bytes {
            return Err(TransportError::ResponseTooLarge);
        }
        parse_http_response(&response)
    }
}

impl HttpTransport for LoopbackTransport {
    fn send<'a>(&'a self, request: Request<Vec<u8>>) -> TransportFuture<'a> {
        Box::pin(async move { self.send_blocking(request) })
    }
}

fn parse_http_response(wire: &[u8]) -> Result<Response<Vec<u8>>, TransportError> {
    let separator = wire
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(TransportError::Protocol)?;
    let head = std::str::from_utf8(&wire[..separator]).map_err(|_| TransportError::Protocol)?;
    let mut lines = head.split("\r\n");
    let status = lines
        .next()
        .and_then(|line| line.split_ascii_whitespace().nth(1))
        .and_then(|value| value.parse::<u16>().ok())
        .and_then(|value| StatusCode::from_u16(value).ok())
        .ok_or(TransportError::Protocol)?;
    let mut headers = HeaderMap::new();
    for line in lines {
        let (name, value) = line.split_once(':').ok_or(TransportError::Protocol)?;
        headers.append(
            HeaderName::from_bytes(name.as_bytes()).map_err(|_| TransportError::Protocol)?,
            HeaderValue::from_str(value.trim()).map_err(|_| TransportError::Protocol)?,
        );
    }
    let body = &wire[separator + 4..];
    let chunked = headers
        .get(http::header::TRANSFER_ENCODING)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.eq_ignore_ascii_case("chunked"));
    let body = if chunked {
        decode_chunked(body)?
    } else {
        body.to_vec()
    };
    if body.len() > MAX_DOCUMENT_BYTES {
        return Err(TransportError::ResponseTooLarge);
    }
    let mut response = Response::builder().status(status);
    if let Some(content_type) = headers.get(CONTENT_TYPE) {
        response = response.header(CONTENT_TYPE, content_type);
    }
    response.body(body).map_err(|_| TransportError::Protocol)
}

fn decode_chunked(mut input: &[u8]) -> Result<Vec<u8>, TransportError> {
    let mut output = Vec::new();
    loop {
        let line_end = input
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(TransportError::Protocol)?;
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|_| TransportError::Protocol)?
            .split(';')
            .next()
            .ok_or(TransportError::Protocol)?;
        let size = usize::from_str_radix(size_text, 16).map_err(|_| TransportError::Protocol)?;
        input = &input[line_end + 2..];
        if size == 0 {
            return Ok(output);
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err(TransportError::Protocol);
        }
        if output.len().saturating_add(size) > MAX_DOCUMENT_BYTES {
            return Err(TransportError::ResponseTooLarge);
        }
        output.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
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
