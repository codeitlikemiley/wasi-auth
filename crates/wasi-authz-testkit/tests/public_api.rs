//! External-path compile checks for the testkit's compatibility re-exports.

use wasi_authz_testkit::{ConformanceProvider, MockProvider};

fn accepts_conformance_provider<P: ConformanceProvider>(_provider: &P) {}

#[test]
fn conformance_provider_remains_importable_from_the_testkit() {
    accepts_conformance_provider(&MockProvider);
}
