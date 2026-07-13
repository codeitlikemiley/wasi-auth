#![no_main]

use http::{HeaderMap, HeaderValue, header::AUTHORIZATION};
use libfuzzer_sys::fuzz_target;
use wasi_http_metadata::{parse_auth_context, strip_reserved_auth_headers};
use wasi_http_policy_core::{RequestIdPolicy, authorization_value};

fuzz_target!(|data: &[u8]| {
    let split = data.len() / 2;
    let mut headers = HeaderMap::new();
    if let Ok(value) = HeaderValue::from_bytes(&data[..split]) {
        headers.append(AUTHORIZATION, value);
    }
    if let Ok(value) = HeaderValue::from_bytes(&data[split..]) {
        headers.append(AUTHORIZATION, value);
    }
    let _authorization = authorization_value(&headers);
    let request_id = RequestIdPolicy.canonicalize(&headers, || "generated-request-id".to_owned());
    assert!(request_id.is_ok());
    let _context = parse_auth_context(&headers);
    strip_reserved_auth_headers(&mut headers);
    assert!(
        headers
            .keys()
            .all(|name| !name.as_str().starts_with("x-wasi-auth-"))
    );
});
