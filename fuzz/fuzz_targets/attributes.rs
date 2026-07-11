#![no_main]

use libfuzzer_sys::fuzz_target;
use wasi_authz_contract::{
    AttributeNameV1, AttributeStringV1, AttributeV1, AttributesV1,
};

fuzz_target!(|data: &[u8]| {
    let text = String::from_utf8_lossy(data);
    let _name = AttributeNameV1::new(text.as_ref());
    let _value = AttributeStringV1::new(text.as_ref());

    if let Ok(attribute) = serde_json::from_slice::<AttributeV1>(data) {
        let encoded = serde_json::to_vec(&attribute)
            .expect("a decoded attribute must remain serializable");
        let round_trip = serde_json::from_slice::<AttributeV1>(&encoded)
            .expect("serialized validated attribute must decode");
        assert_eq!(round_trip, attribute);
    }

    if let Ok(attributes) = serde_json::from_slice::<AttributesV1>(data) {
        let encoded = serde_json::to_vec(&attributes)
            .expect("decoded attributes must remain serializable");
        let round_trip = serde_json::from_slice::<AttributesV1>(&encoded)
            .expect("serialized validated attributes must decode");
        assert_eq!(round_trip, attributes);
    }
});
