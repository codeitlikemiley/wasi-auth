//! Conformance fixtures for `wasi-authz` policy decision providers.
//!
//! Providers can implement [`ConformanceProvider`] and run the same bounded
//! allow, deny, and anonymous-subject cases. The included [`MockProvider`]
//! is deterministic and performs no I/O.

#![deny(rustdoc::broken_intra_doc_links)]

use std::error::Error;
use std::fmt;
#[cfg(test)]
use std::future::Future;

/// Shared provider interface under the conformance-oriented name.
pub use wasi_authz_client::{
    DecisionProvider as ConformanceProvider, ProviderCapability, ProviderFuture,
};
use wasi_authz_contract::{
    AccessRequestV1, ActionNameV1, ActionV1, AuthenticatedSubjectV1, DecisionMetadataV1,
    DecisionResponseV1, EntityIdV1, EntityTypeV1, IssuerV1, ModelNameV1, ModelVersionV1,
    ReasonCodeV1, ResourceV1, SubjectV1,
};

/// AuthZEN document kind represented by a conformance vector.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum ContractVectorKind {
    /// Bounded access-evaluation request.
    Request,
    /// Bounded access-evaluation response.
    Response,
}

/// One versioned golden or negative bounded AuthZEN vector.
#[derive(Clone, Copy, Debug)]
pub struct ContractVector {
    name: &'static str,
    kind: ContractVectorKind,
    document: &'static [u8],
    valid: bool,
}

impl ContractVector {
    /// Returns the stable vector name.
    pub fn name(self) -> &'static str {
        self.name
    }

    /// Returns whether the document is a request or response.
    pub fn kind(self) -> ContractVectorKind {
        self.kind
    }

    /// Returns the checked-in JSON document.
    pub fn document(self) -> &'static [u8] {
        self.document
    }

    /// Returns whether the bounded profile must accept this vector.
    pub fn is_valid(self) -> bool {
        self.valid
    }
}

const CONTRACT_VECTORS: &[ContractVector] = &[
    ContractVector {
        name: "authenticated-request",
        kind: ContractVectorKind::Request,
        document: include_bytes!("../vectors/golden/authenticated-request.json"),
        valid: true,
    },
    ContractVector {
        name: "anonymous-request",
        kind: ContractVectorKind::Request,
        document: include_bytes!("../vectors/golden/anonymous-request.json"),
        valid: true,
    },
    ContractVector {
        name: "allow-response",
        kind: ContractVectorKind::Response,
        document: include_bytes!("../vectors/golden/allow-response.json"),
        valid: true,
    },
    ContractVector {
        name: "deny-response",
        kind: ContractVectorKind::Response,
        document: include_bytes!("../vectors/golden/deny-response.json"),
        valid: true,
    },
    ContractVector {
        name: "response-ignored-standard-fields",
        kind: ContractVectorKind::Response,
        document: include_bytes!("../vectors/golden/response-ignored-standard-fields.json"),
        valid: true,
    },
    ContractVector {
        name: "request-extension-field",
        kind: ContractVectorKind::Request,
        document: include_bytes!("../vectors/golden/request-extension-field.json"),
        valid: true,
    },
    ContractVector {
        name: "request-invalid-anonymous",
        kind: ContractVectorKind::Request,
        document: include_bytes!("../vectors/negative/request-invalid-anonymous.json"),
        valid: false,
    },
    ContractVector {
        name: "response-obligation",
        kind: ContractVectorKind::Response,
        document: include_bytes!("../vectors/negative/response-obligation.json"),
        valid: false,
    },
    ContractVector {
        name: "response-cache",
        kind: ContractVectorKind::Response,
        document: include_bytes!("../vectors/negative/response-cache.json"),
        valid: false,
    },
];

/// Returns all checked-in golden and fail-closed vectors.
pub fn authzen_contract_vectors() -> &'static [ContractVector] {
    CONTRACT_VECTORS
}

/// Failure while validating a checked-in contract vector.
#[derive(Clone, Copy, Debug, Eq, thiserror::Error, PartialEq)]
#[non_exhaustive]
pub enum ContractVectorError {
    /// A golden vector was rejected or failed its encode/decode round trip.
    #[error("golden AuthZEN vector was rejected: {0}")]
    GoldenRejected(&'static str),
    /// A negative vector was incorrectly accepted.
    #[error("negative AuthZEN vector was accepted: {0}")]
    NegativeAccepted(&'static str),
}

/// Validates every checked-in golden and negative AuthZEN vector.
///
/// # Errors
///
/// Returns [`ContractVectorError`] when a golden document is rejected, a
/// negative document is accepted, or a golden round trip changes semantics.
pub fn validate_authzen_contract_vectors() -> Result<(), ContractVectorError> {
    for vector in CONTRACT_VECTORS {
        let accepted = match vector.kind {
            ContractVectorKind::Request => {
                match wasi_authz_contract::AccessEvaluation::from_json_slice(vector.document) {
                    Ok(decoded) => decoded.to_json_vec().is_ok_and(|encoded| {
                        wasi_authz_contract::AccessEvaluation::from_json_slice(&encoded)
                            .is_ok_and(|round_trip| round_trip == decoded)
                    }),
                    Err(_) => false,
                }
            }
            ContractVectorKind::Response => {
                match wasi_authz_contract::DecisionResponseV1::from_json_slice(vector.document) {
                    Ok(decoded) => decoded.to_json_vec().is_ok_and(|encoded| {
                        wasi_authz_contract::DecisionResponseV1::from_json_slice(&encoded)
                            .is_ok_and(|round_trip| round_trip == decoded)
                    }),
                    Err(_) => false,
                }
            }
        };
        match (vector.valid, accepted) {
            (true, false) => return Err(ContractVectorError::GoldenRejected(vector.name)),
            (false, true) => return Err(ContractVectorError::NegativeAccepted(vector.name)),
            _ => {}
        }
    }
    Ok(())
}

/// One deterministic provider conformance case.
#[derive(Clone, Debug)]
pub struct ConformanceCase {
    name: &'static str,
    request: AccessRequestV1,
    expected_allowed: bool,
}

impl ConformanceCase {
    /// Returns the stable case name.
    pub fn name(&self) -> &'static str {
        self.name
    }

    /// Returns the bounded request.
    pub fn request(&self) -> &AccessRequestV1 {
        &self.request
    }

    /// Returns whether the configured provider must allow the request.
    pub fn expected_allowed(&self) -> bool {
        self.expected_allowed
    }
}

/// Shared conformance failure.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum ConformanceError<E>
where
    E: Error + Send + Sync + 'static,
{
    /// The provider failed to produce a decision.
    #[error("provider failed case {case_name}: {source}")]
    Provider {
        /// Stable conformance case name.
        case_name: &'static str,
        /// Provider error.
        #[source]
        source: E,
    },
    /// The provider returned the opposite decision.
    #[error("provider returned the wrong decision for case {case_name}")]
    WrongDecision {
        /// Stable conformance case name.
        case_name: &'static str,
    },
    /// A provider omitted a capability required by the core profile.
    #[error("provider did not declare required capability: {0:?}")]
    MissingCapability(ProviderCapability),
}

/// Runs the shared provider cases in deterministic order.
///
/// Providers must be configured so `document.read` is permitted for the
/// authenticated fixture and all other included requests are denied.
///
/// # Errors
///
/// Returns [`ConformanceError`] when the provider fails or returns the wrong
/// result for any case.
pub async fn run_core_conformance<P>(provider: &P) -> Result<(), ConformanceError<P::Error>>
where
    P: ConformanceProvider,
{
    for required in [
        ProviderCapability::BoundedAuthzenV1,
        ProviderCapability::AnonymousSubjects,
    ] {
        if !provider.capabilities().contains(&required) {
            return Err(ConformanceError::MissingCapability(required));
        }
    }
    for case in core_cases() {
        let response = provider.evaluate(case.request()).await.map_err(|source| {
            ConformanceError::Provider {
                case_name: case.name(),
                source,
            }
        })?;
        if response.is_allowed() != case.expected_allowed() {
            return Err(ConformanceError::WrongDecision {
                case_name: case.name(),
            });
        }
    }
    Ok(())
}

/// Returns the shared authenticated-allow, authenticated-deny, and anonymous-deny cases.
pub fn core_cases() -> Vec<ConformanceCase> {
    vec![
        ConformanceCase {
            name: "authenticated_document_read_is_allowed",
            request: authenticated_request(fixture_action("document.read")),
            expected_allowed: true,
        },
        ConformanceCase {
            name: "authenticated_document_delete_is_denied",
            request: authenticated_request(fixture_action("document.delete")),
            expected_allowed: false,
        },
        ConformanceCase {
            name: "anonymous_document_read_is_denied",
            request: anonymous_request(fixture_action("document.read")),
            expected_allowed: false,
        },
    ]
}

/// Creates the canonical authenticated conformance request.
pub fn authenticated_request(action: ActionNameV1) -> AccessRequestV1 {
    let subject = AuthenticatedSubjectV1::new(
        fixture_entity_type("user"),
        fixture_entity_id("alice"),
        fixture_issuer("https://identity.example"),
    );
    AccessRequestV1::new(
        SubjectV1::Authenticated(subject),
        ActionV1::from_name(action),
        fixture_document(),
    )
}

/// Creates the canonical anonymous conformance request.
pub fn anonymous_request(action: ActionNameV1) -> AccessRequestV1 {
    AccessRequestV1::new(
        SubjectV1::Anonymous,
        ActionV1::from_name(action),
        fixture_document(),
    )
}

/// Deterministic no-I/O provider used by client and PEP tests.
#[derive(Clone, Copy, Debug, Default)]
pub struct MockProvider;

/// Error type for [`MockProvider`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct MockProviderError;

impl fmt::Display for MockProviderError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("mock provider failure")
    }
}

impl Error for MockProviderError {}

impl ConformanceProvider for MockProvider {
    type Error = MockProviderError;

    fn capabilities(&self) -> &'static [ProviderCapability] {
        &[
            ProviderCapability::BoundedAuthzenV1,
            ProviderCapability::AnonymousSubjects,
        ]
    }

    fn evaluate<'a>(&'a self, request: &'a AccessRequestV1) -> ProviderFuture<'a, Self::Error> {
        Box::pin(async move {
            let authenticated = request.subject().is_authenticated();
            let allowed = authenticated && request.action().name().as_str() == "document.read";
            let metadata = DecisionMetadataV1::new()
                .with_model(fixture_model("mock"), fixture_model_version("1"))
                .with_reason_code(fixture_reason(if allowed {
                    "fixture.allow"
                } else {
                    "fixture.deny"
                }));
            Ok(if allowed {
                DecisionResponseV1::allow(metadata)
            } else {
                DecisionResponseV1::deny(metadata)
            })
        })
    }
}

fn fixture_document() -> ResourceV1 {
    ResourceV1::from_parts(
        fixture_entity_type("document"),
        fixture_entity_id("report-1"),
    )
}

fn fixture_entity_type(value: &str) -> EntityTypeV1 {
    match EntityTypeV1::new(value) {
        Ok(value) => value,
        Err(error) => panic!("invalid built-in entity type fixture: {error}"),
    }
}

fn fixture_entity_id(value: &str) -> EntityIdV1 {
    match EntityIdV1::new(value) {
        Ok(value) => value,
        Err(error) => panic!("invalid built-in entity identifier fixture: {error}"),
    }
}

fn fixture_issuer(value: &str) -> IssuerV1 {
    match IssuerV1::new(value) {
        Ok(value) => value,
        Err(error) => panic!("invalid built-in issuer fixture: {error}"),
    }
}

fn fixture_action(value: &str) -> ActionNameV1 {
    match ActionNameV1::new(value) {
        Ok(value) => value,
        Err(error) => panic!("invalid built-in action fixture: {error}"),
    }
}

fn fixture_model(value: &str) -> ModelNameV1 {
    match ModelNameV1::new(value) {
        Ok(value) => value,
        Err(error) => panic!("invalid built-in model fixture: {error}"),
    }
}

fn fixture_model_version(value: &str) -> ModelVersionV1 {
    match ModelVersionV1::new(value) {
        Ok(value) => value,
        Err(error) => panic!("invalid built-in model version fixture: {error}"),
    }
}

fn fixture_reason(value: &str) -> ReasonCodeV1 {
    match ReasonCodeV1::new(value) {
        Ok(value) => value,
        Err(error) => panic!("invalid built-in reason fixture: {error}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_provider_matches_core_conformance_cases() {
        let result = block_on(run_core_conformance(&MockProvider));

        assert!(result.is_ok(), "conformance failed: {result:?}");
    }

    #[test]
    fn checked_in_authzen_vectors_match_the_bounded_contract() {
        let result = validate_authzen_contract_vectors();

        assert!(result.is_ok(), "contract vector failed: {result:?}");
        assert!(
            authzen_contract_vectors()
                .iter()
                .any(|vector| !vector.is_valid())
        );
    }

    fn block_on<F>(future: F) -> F::Output
    where
        F: Future,
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
}
