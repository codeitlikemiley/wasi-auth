#![no_main]

use libfuzzer_sys::fuzz_target;
use wasi_authz_contract::{AccessEvaluation, DecisionResponseV1, MAX_DOCUMENT_BYTES};

fuzz_target!(|data: &[u8]| {
    assert!(
        AccessEvaluation::from_json_slice(
            br#"{
                "subject":{"type":"anonymous","id":"anonymous","properties":{"wasi_authz":{"state":"anonymous"}},"vendor_extension":true},
                "action":{"name":"document.read","properties":{"wasi_authz":{}}},
                "resource":{"type":"document","id":"report-1","properties":{"wasi_authz":{}}},
                "vendor_extension":{"revision":2}
            }"#
        )
        .is_ok()
    );
    assert!(
        DecisionResponseV1::from_json_slice(
            br#"{"decision":true,"context":{"obligations":[],"vendor":true}}"#
        )
        .is_ok()
    );
    assert!(
        DecisionResponseV1::from_json_slice(
            br#"{"decision":true,"context":{"obligations":[{"name":"audit"}]}}"#
        )
        .is_err()
    );
    assert!(
        DecisionResponseV1::from_json_slice(
            br#"{"decision":true,"context":{"obligations":"none"}}"#
        )
        .is_err()
    );
    assert!(
        DecisionResponseV1::from_json_slice(
            br#"{"decision":true,"context":{"wasi_authz":{"unknown":true}}}"#
        )
        .is_err()
    );

    if let Ok(evaluation) = AccessEvaluation::from_json_slice(data) {
        let encoded = evaluation
            .to_json_vec()
            .expect("a decoded evaluation must remain encodable");
        assert!(encoded.len() <= MAX_DOCUMENT_BYTES);
        let round_trip = AccessEvaluation::from_json_slice(&encoded)
            .expect("serialized validated evaluation must decode");
        assert_eq!(round_trip, evaluation);
    }

    if let Ok(decision) = DecisionResponseV1::from_json_slice(data) {
        let encoded = decision
            .to_json_vec()
            .expect("a decoded decision must remain encodable");
        assert!(encoded.len() <= MAX_DOCUMENT_BYTES);
        let round_trip = DecisionResponseV1::from_json_slice(&encoded)
            .expect("serialized validated decision must decode");
        assert_eq!(round_trip, decision);
    }
});
