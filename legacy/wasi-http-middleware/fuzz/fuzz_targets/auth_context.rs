#![no_main]

use http::HeaderValue;
use libfuzzer_sys::fuzz_target;
use wasi_http_metadata::{
    MAX_AUTH_CONTEXT_ENCODED_LEN, decode_auth_context, encode_auth_context,
};

fuzz_target!(|data: &[u8]| {
    let Ok(value) = HeaderValue::from_bytes(data) else {
        return;
    };
    if let Ok(context) = decode_auth_context(&value) {
        let encoded = encode_auth_context(&context).expect("decoded contexts must re-encode");
        assert!(encoded.as_bytes().len() <= MAX_AUTH_CONTEXT_ENCODED_LEN);
        assert_eq!(decode_auth_context(&encoded), Ok(context));
    }
});
