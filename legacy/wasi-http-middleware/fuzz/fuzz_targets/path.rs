#![no_main]

use libfuzzer_sys::fuzz_target;
use wasi_http_policy_core::normalize_policy_path;

fuzz_target!(|value: &str| {
    if let Ok(path) = normalize_policy_path(value) {
        assert!(path.starts_with('/'));
        assert!(!path.contains('?'));
        assert!(!path.contains('\\'));
        assert!(!path.contains("//"));
        assert_eq!(normalize_policy_path(&path), Ok(path.clone()));
    }
});
