//! SpiceDB `CheckPermission` adapter with explicit consistency semantics.
//!
//! The adapter speaks the official JSON-transcoded v1 API through the shared
//! transport trait. Provider credentials remain outside authorization request
//! data and should be supplied by a custom transport or host mTLS.

#![deny(rustdoc::broken_intra_doc_links)]

use std::collections::BTreeMap;
use std::fmt;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::header::{ACCEPT, CONTENT_LENGTH, CONTENT_TYPE};
use http::{Request, StatusCode, Uri};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;
use wasi_authz_client::{
    DecisionProvider, HttpTransport, ProviderCapability, ProviderFuture, TransportError,
};
use wasi_authz_contract::{
    AccessEvaluation, AttributeProvenanceV1, AttributeValueV1, AttributesV1,
    ConsistencyRequirementV1, ConsistencyTokenV1, DecisionMetadataV1, DecisionResponseV1,
    MAX_DOCUMENT_BYTES, ModelNameV1, ModelVersionV1, PolicyRevisionV1, ReasonCodeV1, SubjectV1,
};

const CHECK_PERMISSION_PATH: &str = "/v1/permissions/check";
const CAPABILITIES: &[ProviderCapability] = &[
    ProviderCapability::BoundedAuthzenV1,
    ProviderCapability::AnonymousSubjects,
    ProviderCapability::TypedAttributes,
    ProviderCapability::AttributeProvenance,
    ProviderCapability::RelationshipHierarchy,
    ProviderCapability::MinimizeLatencyConsistency,
    ProviderCapability::AtLeastAsFreshConsistency,
    ProviderCapability::FullyConsistentConsistency,
];

/// Validated SpiceDB HTTP endpoint.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SpiceDbEndpoint(Uri);

impl SpiceDbEndpoint {
    /// Validates a production CheckPermission endpoint.
    ///
    /// Remote endpoints require HTTPS. HTTP is allowed for an internal Spin
    /// component hostname ending in `.spin.internal`.
    ///
    /// # Errors
    ///
    /// Returns [`SpiceDbError::InvalidEndpoint`] for any endpoint outside this
    /// policy.
    pub fn new(value: impl AsRef<str>) -> Result<Self, SpiceDbError> {
        let uri = parse_endpoint(value.as_ref())?;
        let scheme = uri.scheme_str();
        let host = uri.host();
        let allowed = scheme == Some("https")
            || (scheme == Some("http")
                && host.is_some_and(|host| host.ends_with(".spin.internal")));
        if !allowed {
            return Err(SpiceDbError::InvalidEndpoint);
        }
        Ok(Self(uri))
    }

    /// Validates an explicit HTTP loopback endpoint for local development.
    ///
    /// # Errors
    ///
    /// Returns [`SpiceDbError::InvalidEndpoint`] unless the host is loopback.
    pub fn new_loopback_for_dev(value: impl AsRef<str>) -> Result<Self, SpiceDbError> {
        let uri = parse_endpoint(value.as_ref())?;
        let loopback = uri
            .host()
            .is_some_and(|host| matches!(host, "localhost" | "127.0.0.1" | "::1" | "[::1]"));
        if uri.scheme_str() != Some("http") || !loopback {
            return Err(SpiceDbError::InvalidEndpoint);
        }
        Ok(Self(uri))
    }

    /// Returns the validated URI.
    pub fn as_uri(&self) -> &Uri {
        &self.0
    }
}

fn parse_endpoint(value: &str) -> Result<Uri, SpiceDbError> {
    let uri = value
        .parse::<Uri>()
        .map_err(|_| SpiceDbError::InvalidEndpoint)?;
    let valid = uri
        .authority()
        .is_some_and(|authority| !authority.as_str().contains('@'))
        && uri.path() == CHECK_PERMISSION_PATH
        && uri.query().is_none();
    if !valid {
        return Err(SpiceDbError::InvalidEndpoint);
    }
    Ok(uri)
}

/// Explicit stable action-to-SpiceDB-permission map.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct PermissionMap(BTreeMap<String, String>);

impl PermissionMap {
    /// Validates and constructs a permission map.
    ///
    /// Explicit mapping prevents punctuation normalization collisions between
    /// domain actions and SpiceDB permission names.
    ///
    /// # Errors
    ///
    /// Returns [`SpiceDbError`] for invalid or duplicate actions/permissions.
    pub fn new<I, A, P>(mappings: I) -> Result<Self, SpiceDbError>
    where
        I: IntoIterator<Item = (A, P)>,
        A: Into<String>,
        P: Into<String>,
    {
        let mut result = BTreeMap::new();
        for (action, permission) in mappings {
            let action = action.into();
            wasi_authz_contract::ActionNameV1::new(action.clone())
                .map_err(|_| SpiceDbError::InvalidPermissionMap)?;
            let permission = permission.into();
            if !is_spicedb_name(&permission) || result.insert(action, permission).is_some() {
                return Err(SpiceDbError::InvalidPermissionMap);
            }
        }
        if result.is_empty() {
            return Err(SpiceDbError::InvalidPermissionMap);
        }
        Ok(Self(result))
    }

    fn permission_for(&self, action: &str) -> Result<&str, SpiceDbError> {
        self.0
            .get(action)
            .map(String::as_str)
            .ok_or(SpiceDbError::UnmappedAction)
    }
}

/// SpiceDB adapter failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SpiceDbError {
    /// The CheckPermission endpoint violated transport policy.
    #[error("invalid SpiceDB CheckPermission endpoint")]
    InvalidEndpoint,
    /// The action-to-permission map was invalid.
    #[error("invalid SpiceDB permission map")]
    InvalidPermissionMap,
    /// No SpiceDB permission was configured for the action.
    #[error("authorization action has no SpiceDB permission mapping")]
    UnmappedAction,
    /// A resource, subject, or permission violated SpiceDB naming rules.
    #[error("authorization input is not representable in SpiceDB")]
    InvalidReference,
    /// The outbound HTTP transport failed.
    #[error("SpiceDB transport failed")]
    Transport(#[source] TransportError),
    /// SpiceDB rejected provider authentication.
    #[error("SpiceDB rejected PEP authentication")]
    ProviderAuthentication,
    /// SpiceDB was unavailable or returned an invalid response.
    #[error("SpiceDB provider is unavailable")]
    ProviderUnavailable,
    /// SpiceDB returned an invalid or unsupported response.
    #[error("invalid SpiceDB CheckPermission response")]
    InvalidResponse,
    /// The permission depends on caveat inputs that were not resolved.
    #[error("SpiceDB returned a conditional permission")]
    ConditionalPermission,
    /// Bounded model metadata was invalid.
    #[error("invalid SpiceDB decision metadata")]
    InvalidMetadata,
}

/// SpiceDB CheckPermission decision provider.
#[derive(Clone)]
pub struct SpiceDbProvider<T> {
    endpoint: SpiceDbEndpoint,
    transport: T,
    permissions: PermissionMap,
    schema_revision: PolicyRevisionV1,
    model_version: ModelVersionV1,
}

impl<T> fmt::Debug for SpiceDbProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpiceDbProvider")
            .field("endpoint", &"[REDACTED]")
            .field("transport", &"[REDACTED]")
            .field("permissions", &self.permissions)
            .field("schema_revision", &"[REDACTED]")
            .field("model_version", &self.model_version.as_str())
            .finish()
    }
}

impl<T> SpiceDbProvider<T>
where
    T: HttpTransport,
{
    /// Constructs a provider with explicit action mappings and model metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SpiceDbError`] for invalid bounded metadata.
    pub fn new(
        endpoint: SpiceDbEndpoint,
        transport: T,
        permissions: PermissionMap,
        schema_revision: impl Into<String>,
        model_version: impl Into<String>,
    ) -> Result<Self, SpiceDbError> {
        Ok(Self {
            endpoint,
            transport,
            permissions,
            schema_revision: PolicyRevisionV1::new(schema_revision)
                .map_err(|_| SpiceDbError::InvalidMetadata)?,
            model_version: ModelVersionV1::new(model_version)
                .map_err(|_| SpiceDbError::InvalidMetadata)?,
        })
    }

    async fn evaluate_inner(
        &self,
        evaluation: &AccessEvaluation,
    ) -> Result<DecisionResponseV1, SpiceDbError> {
        let SubjectV1::Authenticated(subject) = evaluation.subject() else {
            return self.decision(false, None);
        };
        let resource_type = evaluation.resource().resource_type().as_str();
        let resource_id = evaluation.resource().id().as_str();
        let subject_type = subject.subject_type().as_str();
        if !is_spicedb_name(resource_type)
            || !is_spicedb_name(subject_type)
            || !is_spicedb_id(resource_id)
        {
            return Err(SpiceDbError::InvalidReference);
        }
        let subject_id = canonical_subject_id(subject);
        if !is_spicedb_id(&subject_id) {
            return Err(SpiceDbError::InvalidReference);
        }
        let permission = self
            .permissions
            .permission_for(evaluation.action().name().as_str())?;
        let wire = CheckPermissionRequest {
            consistency: consistency(evaluation),
            resource: ObjectReference {
                object_type: resource_type,
                object_id: resource_id,
            },
            permission,
            subject: SubjectReference {
                object: ObjectReference {
                    object_type: subject_type,
                    object_id: &subject_id,
                },
            },
            context: caveat_context(evaluation)?,
        };
        let body = serde_json::to_vec(&wire).map_err(|_| SpiceDbError::InvalidReference)?;
        if body.len() > MAX_DOCUMENT_BYTES {
            return Err(SpiceDbError::InvalidReference);
        }
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(self.endpoint.as_uri().clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .body(body)
            .map_err(|_| SpiceDbError::InvalidReference)?;
        let response = self
            .transport
            .send(request)
            .await
            .map_err(SpiceDbError::Transport)?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(SpiceDbError::ProviderAuthentication);
            }
            _ => return Err(SpiceDbError::ProviderUnavailable),
        }
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if content_type != Some("application/json") || response.body().len() > MAX_DOCUMENT_BYTES {
            return Err(SpiceDbError::InvalidResponse);
        }
        let response: CheckPermissionResponse =
            serde_json::from_slice(response.body()).map_err(|_| SpiceDbError::InvalidResponse)?;
        if response.partial_caveat_info.is_some() {
            return Err(SpiceDbError::ConditionalPermission);
        }
        let token = response
            .checked_at
            .ok_or(SpiceDbError::InvalidResponse)?
            .token;
        let token = ConsistencyTokenV1::new(token).map_err(|_| SpiceDbError::InvalidResponse)?;
        match response.permissionship.as_str() {
            "PERMISSIONSHIP_HAS_PERMISSION" => self.decision(true, Some(token)),
            "PERMISSIONSHIP_NO_PERMISSION" => self.decision(false, Some(token)),
            "PERMISSIONSHIP_CONDITIONAL_PERMISSION" => Err(SpiceDbError::ConditionalPermission),
            _ => Err(SpiceDbError::InvalidResponse),
        }
    }

    fn decision(
        &self,
        allowed: bool,
        token: Option<ConsistencyTokenV1>,
    ) -> Result<DecisionResponseV1, SpiceDbError> {
        let mut metadata = DecisionMetadataV1::new()
            .with_policy_revision(self.schema_revision.clone())
            .with_model(
                ModelNameV1::new("spicedb").map_err(|_| SpiceDbError::InvalidMetadata)?,
                self.model_version.clone(),
            )
            .with_reason_code(
                ReasonCodeV1::new(if allowed {
                    "spicedb.allow"
                } else {
                    "spicedb.deny"
                })
                .map_err(|_| SpiceDbError::InvalidMetadata)?,
            );
        if let Some(token) = token {
            metadata = metadata.with_consistency_token(token);
        }
        Ok(if allowed {
            DecisionResponseV1::allow(metadata)
        } else {
            DecisionResponseV1::deny(metadata)
        })
    }
}

impl<T> DecisionProvider for SpiceDbProvider<T>
where
    T: HttpTransport,
{
    type Error = SpiceDbError;

    fn capabilities(&self) -> &'static [ProviderCapability] {
        CAPABILITIES
    }

    fn evaluate<'a>(&'a self, evaluation: &'a AccessEvaluation) -> ProviderFuture<'a, Self::Error> {
        Box::pin(self.evaluate_inner(evaluation))
    }
}

/// Returns the canonical SpiceDB ID for an issuer-scoped subject.
pub fn canonical_subject_id(subject: &wasi_authz_contract::AuthenticatedSubjectV1) -> String {
    let mut identity =
        Vec::with_capacity(subject.issuer().as_str().len() + subject.id().as_str().len() + 1);
    identity.extend_from_slice(subject.issuer().as_str().as_bytes());
    identity.push(0);
    identity.extend_from_slice(subject.id().as_str().as_bytes());
    format!("v1_{}", URL_SAFE_NO_PAD.encode(identity))
}

fn consistency(evaluation: &AccessEvaluation) -> Value {
    match evaluation
        .context()
        .and_then(wasi_authz_contract::ContextV1::consistency)
    {
        Some(ConsistencyRequirementV1::AtLeastAsFresh { token }) => {
            json!({"atLeastAsFresh": {"token": token.as_str()}})
        }
        Some(ConsistencyRequirementV1::FullyConsistent) => json!({"fullyConsistent": true}),
        Some(ConsistencyRequirementV1::MinimizeLatency) | None => {
            json!({"minimizeLatency": true})
        }
        _ => json!({"fullyConsistent": true}),
    }
}

fn caveat_context(evaluation: &AccessEvaluation) -> Result<Option<Value>, SpiceDbError> {
    let mut context = Map::new();
    if let Some(request_context) = evaluation.context() {
        context.extend(attributes_to_json(request_context.attributes())?);
    }
    if let SubjectV1::Authenticated(subject) = evaluation.subject() {
        context.insert(
            "wasi_subject".to_owned(),
            json!({
                "issuer": subject.issuer().as_str(),
                "tenant_id": subject.tenant_id().map(|value| value.as_str()),
                "scopes": subject.scopes().iter().map(|scope| scope.as_str()).collect::<Vec<_>>(),
                "attributes": attributes_to_json(subject.attributes())?,
            }),
        );
    }
    context.insert(
        "wasi_action_attributes".to_owned(),
        Value::Object(attributes_to_json(evaluation.action().attributes())?),
    );
    context.insert(
        "wasi_resource_attributes".to_owned(),
        Value::Object(attributes_to_json(evaluation.resource().attributes())?),
    );
    Ok(if context.is_empty() {
        None
    } else {
        Some(Value::Object(context))
    })
}

fn attributes_to_json(attributes: &AttributesV1) -> Result<Map<String, Value>, SpiceDbError> {
    let mut result = Map::new();
    for attribute in attributes.as_slice() {
        result.insert(
            attribute.name().as_str().to_owned(),
            json!({
                "value": attribute_value(attribute.value())?,
                "provenance": provenance(attribute.provenance()),
            }),
        );
    }
    Ok(result)
}

fn attribute_value(value: &AttributeValueV1) -> Result<Value, SpiceDbError> {
    Ok(match value {
        AttributeValueV1::String(value) => json!(value.as_str()),
        AttributeValueV1::Integer(value) => json!(value),
        AttributeValueV1::Boolean(value) => json!(value),
        AttributeValueV1::StringList(values) => {
            json!(
                values
                    .as_slice()
                    .iter()
                    .map(|value| value.as_str())
                    .collect::<Vec<_>>()
            )
        }
        _ => return Err(SpiceDbError::InvalidReference),
    })
}

fn provenance(value: AttributeProvenanceV1) -> &'static str {
    match value {
        AttributeProvenanceV1::IdentityProvider => "identity_provider",
        AttributeProvenanceV1::ResourceStore => "resource_store",
        AttributeProvenanceV1::Application => "application",
        AttributeProvenanceV1::Gateway => "gateway",
        AttributeProvenanceV1::PolicyInformationPoint => "policy_information_point",
        _ => "unknown",
    }
}

fn is_spicedb_name(value: &str) -> bool {
    (3..=64).contains(&value.len())
        && value
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_lowercase())
        && value
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_spicedb_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1024
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'|' | b'-' | b'=' | b'+')
        })
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckPermissionRequest<'a> {
    consistency: Value,
    resource: ObjectReference<'a>,
    permission: &'a str,
    subject: SubjectReference<'a>,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ObjectReference<'a> {
    object_type: &'a str,
    object_id: &'a str,
}

#[derive(Serialize)]
struct SubjectReference<'a> {
    object: ObjectReference<'a>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckPermissionResponse {
    checked_at: Option<ZedToken>,
    permissionship: String,
    #[serde(default)]
    partial_caveat_info: Option<Value>,
    #[serde(default, rename = "debugTrace")]
    _debug_trace: Option<Value>,
    #[serde(default, rename = "optionalExpiresAt")]
    _optional_expires_at: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ZedToken {
    token: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::Response;
    use std::sync::Mutex;
    use wasi_authz_client::TransportFuture;
    use wasi_authz_contract::{ActionNameV1, ContextV1};
    use wasi_authz_testkit::run_core_conformance;

    #[derive(Debug, Default)]
    struct MockSpiceDbTransport {
        requests: Mutex<Vec<Value>>,
    }

    impl HttpTransport for MockSpiceDbTransport {
        fn send<'a>(&'a self, request: Request<Vec<u8>>) -> TransportFuture<'a> {
            Box::pin(async move {
                let value: Value =
                    serde_json::from_slice(request.body()).map_err(|_| TransportError::Protocol)?;
                let allowed = value["permission"] == "read";
                self.requests
                    .lock()
                    .map_err(|_| TransportError::Unavailable)?
                    .push(value);
                Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(
                        json!({
                            "checkedAt": {"token": "zed-token-1"},
                            "permissionship": if allowed {
                                "PERMISSIONSHIP_HAS_PERMISSION"
                            } else {
                                "PERMISSIONSHIP_NO_PERMISSION"
                            },
                            "partialCaveatInfo": null,
                            "debugTrace": null,
                            "optionalExpiresAt": null
                        })
                        .to_string()
                        .into_bytes(),
                    )
                    .map_err(|_| TransportError::Protocol)
            })
        }
    }

    #[test]
    fn provider_passes_shared_conformance() {
        let provider = fixture_provider(MockSpiceDbTransport::default());

        let result = block_on(run_core_conformance(&provider));

        assert!(result.is_ok(), "conformance failed: {result:?}");
    }

    #[test]
    fn every_consistency_mode_maps_to_the_official_json_shape() {
        let provider = fixture_provider(MockSpiceDbTransport::default());
        let base = wasi_authz_testkit::authenticated_request(
            ActionNameV1::new("document.read").expect("valid fixture"),
        );
        let at_least = base.clone().with_context(ContextV1::new().with_consistency(
            ConsistencyRequirementV1::AtLeastAsFresh {
                token: ConsistencyTokenV1::new("minimum-token").expect("valid fixture"),
            },
        ));
        let fully_consistent = base.clone().with_context(
            ContextV1::new().with_consistency(ConsistencyRequirementV1::FullyConsistent),
        );

        let minimize = block_on(provider.evaluate_inner(&base)).expect("provider evaluates");
        let full =
            block_on(provider.evaluate_inner(&fully_consistent)).expect("provider evaluates");
        let fresh = block_on(provider.evaluate_inner(&at_least)).expect("provider evaluates");

        assert!(minimize.is_allowed());
        assert!(full.is_allowed());
        assert!(fresh.is_allowed());
        let requests = provider
            .transport
            .requests
            .lock()
            .expect("fixture mutex is healthy");
        assert_eq!(
            requests[2]["consistency"]["atLeastAsFresh"]["token"],
            "minimum-token"
        );
        assert_eq!(requests[0]["consistency"]["minimizeLatency"], true);
        assert_eq!(requests[1]["consistency"]["fullyConsistent"], true);
        assert!(
            provider
                .capabilities()
                .contains(&ProviderCapability::AtLeastAsFreshConsistency)
        );
    }

    #[test]
    fn canonical_subject_id_is_issuer_scoped() {
        let mut first = wasi_authz_testkit::authenticated_request(
            ActionNameV1::new("document.read").expect("valid fixture"),
        );
        let SubjectV1::Authenticated(first_subject) = first.subject().clone() else {
            panic!("fixture must be authenticated");
        };
        let second_subject = wasi_authz_contract::AuthenticatedSubjectV1::new(
            first_subject.subject_type().clone(),
            first_subject.id().clone(),
            wasi_authz_contract::IssuerV1::new("https://other-issuer.example")
                .expect("valid fixture"),
        );

        assert_ne!(
            canonical_subject_id(&first_subject),
            canonical_subject_id(&second_subject)
        );
        first = first.with_context(ContextV1::new());
        assert!(first.context().is_some());
    }

    #[test]
    fn provider_debug_redacts_endpoint_transport_and_revision() {
        let provider = SpiceDbProvider::new(
            SpiceDbEndpoint::new("https://endpoint-secret.example/v1/permissions/check")
                .expect("valid fixture"),
            MockSpiceDbTransport::default(),
            PermissionMap::new([("document.read", "read")]).expect("valid fixture"),
            "revision-secret",
            "spicedb-1.54.0",
        )
        .expect("valid fixture");

        let debug = format!("{provider:?}");

        assert!(!debug.contains("endpoint-secret"));
        assert!(!debug.contains("revision-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    fn fixture_provider(transport: MockSpiceDbTransport) -> SpiceDbProvider<MockSpiceDbTransport> {
        SpiceDbProvider::new(
            SpiceDbEndpoint::new("https://spicedb.example/v1/permissions/check")
                .expect("valid fixture"),
            transport,
            PermissionMap::new([("document.read", "read"), ("document.delete", "delete")])
                .expect("valid fixture"),
            "schema-1",
            "spicedb-1.54.0",
        )
        .expect("valid fixture")
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
}
