#![no_main]

use std::future::ready;

use futures::executor::block_on;
use http::header::CONTENT_TYPE;
use http::{HeaderValue, Request, Response};
use libfuzzer_sys::fuzz_target;
use wasi_authz_client::{
    AuthzenClient, AuthzenEndpoint, HttpTransport, TransportError, TransportFuture,
};
use wasi_authz_contract::{
    AccessEvaluation, Action, Resource, SubjectV1, MAX_DOCUMENT_BYTES,
};

#[derive(Debug)]
struct FuzzTransport {
    status: u16,
    content_type: Option<HeaderValue>,
    body: Vec<u8>,
}

impl HttpTransport for FuzzTransport {
    fn send<'a>(&'a self, _request: Request<Vec<u8>>) -> TransportFuture<'a> {
        let mut response = Response::builder().status(self.status);
        if let Some(content_type) = &self.content_type {
            response = response.header(CONTENT_TYPE, content_type);
        }
        let result = response
            .body(self.body.clone())
            .map_err(|_| TransportError::Protocol);
        Box::pin(ready(result))
    }
}

fuzz_target!(|data: &[u8]| {
    let status = data
        .get(..2)
        .map(|bytes| u16::from_le_bytes([bytes[0], bytes[1]]))
        .unwrap_or(200);
    let header_end = data.len().min(130);
    let content_type = data
        .get(2..header_end)
        .and_then(|bytes| HeaderValue::from_bytes(bytes).ok());
    let body = data.get(header_end..).unwrap_or_default().to_vec();
    let transport = FuzzTransport {
        status,
        content_type,
        body,
    };
    let endpoint = AuthzenEndpoint::new_loopback_for_dev(
        "http://127.0.0.1/access/v1/evaluation",
    )
    .expect("fixed loopback endpoint is valid");
    let action = Action::new("fuzz.read").expect("fixed action is valid");
    let resource = Resource::new("document", "resource-1")
        .expect("fixed resource is valid");
    let evaluation = AccessEvaluation::new(SubjectV1::Anonymous, action, resource);
    if let Ok(decision) = block_on(AuthzenClient::new(endpoint, transport).evaluate(&evaluation)) {
        let encoded = decision
            .to_json_vec()
            .expect("validated decision must encode");
        assert!(encoded.len() <= MAX_DOCUMENT_BYTES);
    }
});
