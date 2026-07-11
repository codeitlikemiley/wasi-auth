//! Embedded Cedar policy decision provider.
//!
//! Contract attributes become Cedar records with `value` and `provenance`
//! fields, allowing policies to make provenance-aware RBAC and ABAC choices.
//! Cedar evaluation errors are indeterminate provider failures, never denials.

#![deny(rustdoc::broken_intra_doc_links)]

use std::fmt;
use std::str::FromStr as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cedar_policy::{
    Authorizer, Context, Decision, Entities, EntityId, EntityTypeName, EntityUid, PolicySet,
    Request, Schema, ValidationMode, Validator,
};
use serde_json::{Map, Value, json};
use thiserror::Error;
use wasi_authz_client::{DecisionProvider, ProviderCapability, ProviderFuture};
use wasi_authz_contract::{
    AccessEvaluation, AttributeProvenanceV1, AttributeValueV1, AttributesV1,
    ConsistencyRequirementV1, DecisionMetadataV1, DecisionResponseV1, ModelNameV1, ModelVersionV1,
    PolicyRevisionV1, ReasonCodeV1, SubjectV1,
};

const CAPABILITIES: &[ProviderCapability] = &[
    ProviderCapability::BoundedAuthzenV1,
    ProviderCapability::AnonymousSubjects,
    ProviderCapability::TypedAttributes,
    ProviderCapability::AttributeProvenance,
    ProviderCapability::RelationshipHierarchy,
    ProviderCapability::MinimizeLatencyConsistency,
    ProviderCapability::FullyConsistentConsistency,
];

/// Cedar adapter configuration or evaluation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CedarError {
    /// The Cedar policy source was syntactically invalid.
    #[error("invalid Cedar policy set")]
    InvalidPolicy,
    /// The Cedar schema source was invalid.
    #[error("invalid Cedar schema")]
    InvalidSchema,
    /// The policy set failed strict schema validation.
    #[error("Cedar policy validation failed")]
    PolicyValidation,
    /// A policy revision or model version violated the bounded contract.
    #[error("invalid Cedar decision metadata")]
    InvalidMetadata,
    /// A contract entity type or attribute name was not a Cedar identifier.
    #[error("authorization input is not representable in Cedar")]
    InvalidIdentifier,
    /// Cedar entity or context conversion failed.
    #[error("invalid Cedar entity data")]
    InvalidEntity,
    /// Cedar rejected the typed authorization request.
    #[error("invalid Cedar authorization request")]
    InvalidRequest,
    /// One or more Cedar policies failed during evaluation.
    #[error("Cedar authorization evaluation was indeterminate")]
    Indeterminate,
    /// The embedded snapshot cannot satisfy an at-least-as-fresh provider token.
    #[error("Cedar does not support the requested consistency mode")]
    UnsupportedConsistency,
}

/// Parsed embedded Cedar provider.
#[derive(Clone)]
pub struct CedarProvider {
    policies: PolicySet,
    schema: Option<Schema>,
    trusted_entities: Entities,
    policy_revision: PolicyRevisionV1,
    model_version: ModelVersionV1,
}

impl fmt::Debug for CedarProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CedarProvider")
            .field("policies", &"[REDACTED]")
            .field("schema_configured", &self.schema.is_some())
            .field("trusted_entities", &"[REDACTED]")
            .field("policy_revision", &"[REDACTED]")
            .field("model_version", &self.model_version.as_str())
            .finish()
    }
}

impl CedarProvider {
    /// Parses a Cedar policy set and entity graph without schema validation.
    ///
    /// This constructor exists for tests and local prototypes. Production
    /// policy activation should use [`Self::new_validated`].
    ///
    /// # Errors
    ///
    /// Returns [`CedarError`] for invalid policy or bounded metadata.
    pub fn new_unvalidated_for_test(
        policy_source: &str,
        trusted_entities_json: &str,
        policy_revision: impl Into<String>,
        model_version: impl Into<String>,
    ) -> Result<Self, CedarError> {
        let policies = PolicySet::from_str(policy_source).map_err(|_| CedarError::InvalidPolicy)?;
        let trusted_entities = Entities::from_json_str(trusted_entities_json, None)
            .map_err(|_| CedarError::InvalidEntity)?;
        Ok(Self {
            policies,
            schema: None,
            trusted_entities,
            policy_revision: PolicyRevisionV1::new(policy_revision)
                .map_err(|_| CedarError::InvalidMetadata)?,
            model_version: ModelVersionV1::new(model_version)
                .map_err(|_| CedarError::InvalidMetadata)?,
        })
    }

    /// Parses a schema and strictly validates the Cedar policy set.
    ///
    /// # Errors
    ///
    /// Returns [`CedarError`] for invalid schema, policy, validation, or
    /// bounded metadata.
    pub fn new_validated(
        policy_source: &str,
        schema_source: &str,
        trusted_entities_json: &str,
        policy_revision: impl Into<String>,
        model_version: impl Into<String>,
    ) -> Result<Self, CedarError> {
        let policies = PolicySet::from_str(policy_source).map_err(|_| CedarError::InvalidPolicy)?;
        let schema = Schema::from_json_str(schema_source).map_err(|_| CedarError::InvalidSchema)?;
        let validation = Validator::new(schema.clone()).validate(&policies, ValidationMode::Strict);
        if !validation.validation_passed() {
            return Err(CedarError::PolicyValidation);
        }
        let trusted_entities = Entities::from_json_str(trusted_entities_json, Some(&schema))
            .map_err(|_| CedarError::InvalidEntity)?;
        Ok(Self {
            policies,
            schema: Some(schema),
            trusted_entities,
            policy_revision: PolicyRevisionV1::new(policy_revision)
                .map_err(|_| CedarError::InvalidMetadata)?,
            model_version: ModelVersionV1::new(model_version)
                .map_err(|_| CedarError::InvalidMetadata)?,
        })
    }

    /// Evaluates one bounded request synchronously.
    ///
    /// # Errors
    ///
    /// Returns [`CedarError`] when conversion or policy evaluation is
    /// indeterminate. Such errors must fail closed at the PEP.
    pub fn evaluate_sync(
        &self,
        evaluation: &AccessEvaluation,
    ) -> Result<DecisionResponseV1, CedarError> {
        if matches!(
            evaluation
                .context()
                .and_then(wasi_authz_contract::ContextV1::consistency),
            Some(ConsistencyRequirementV1::AtLeastAsFresh { .. })
        ) {
            return Err(CedarError::UnsupportedConsistency);
        }
        let principal = principal_uid(evaluation.subject())?;
        let action = uid("Action", evaluation.action().name().as_str())?;
        let resource = uid(
            evaluation.resource().resource_type().as_str(),
            evaluation.resource().id().as_str(),
        )?;
        let entities = entities(
            evaluation,
            &principal,
            &resource,
            self.schema.as_ref(),
            &self.trusted_entities,
        )?;
        let context = request_context(evaluation, &action, self.schema.as_ref())?;
        let request = Request::new(principal, action, resource, context, self.schema.as_ref())
            .map_err(|_| CedarError::InvalidRequest)?;
        let response = Authorizer::new().is_authorized(&request, &self.policies, &entities);
        if response.diagnostics().errors().next().is_some() {
            return Err(CedarError::Indeterminate);
        }
        self.decision(response.decision() == Decision::Allow)
    }

    fn decision(&self, allowed: bool) -> Result<DecisionResponseV1, CedarError> {
        let metadata = DecisionMetadataV1::new()
            .with_policy_revision(self.policy_revision.clone())
            .with_model(
                ModelNameV1::new("cedar").map_err(|_| CedarError::InvalidMetadata)?,
                self.model_version.clone(),
            )
            .with_reason_code(
                ReasonCodeV1::new(if allowed { "cedar.allow" } else { "cedar.deny" })
                    .map_err(|_| CedarError::InvalidMetadata)?,
            );
        Ok(if allowed {
            DecisionResponseV1::allow(metadata)
        } else {
            DecisionResponseV1::deny(metadata)
        })
    }
}

/// Returns the canonical Cedar ID for an issuer-scoped authenticated subject.
///
/// The encoding is base64url without padding over `issuer`, a NUL delimiter,
/// and the subject ID. The delimiter is unambiguous because contract values
/// reject control characters.
pub fn canonical_principal_id(subject: &wasi_authz_contract::AuthenticatedSubjectV1) -> String {
    let mut identity =
        Vec::with_capacity(subject.issuer().as_str().len() + subject.id().as_str().len() + 1);
    identity.extend_from_slice(subject.issuer().as_str().as_bytes());
    identity.push(0);
    identity.extend_from_slice(subject.id().as_str().as_bytes());
    format!("v1_{}", URL_SAFE_NO_PAD.encode(identity))
}

impl DecisionProvider for CedarProvider {
    type Error = CedarError;

    fn capabilities(&self) -> &'static [ProviderCapability] {
        CAPABILITIES
    }

    fn evaluate<'a>(&'a self, evaluation: &'a AccessEvaluation) -> ProviderFuture<'a, Self::Error> {
        Box::pin(async move { self.evaluate_sync(evaluation) })
    }
}

fn principal_uid(subject: &SubjectV1) -> Result<EntityUid, CedarError> {
    match subject {
        SubjectV1::Anonymous => uid("Anonymous", "anonymous"),
        SubjectV1::Authenticated(subject) => uid(
            subject.subject_type().as_str(),
            &canonical_principal_id(subject),
        ),
        _ => Err(CedarError::InvalidRequest),
    }
}

fn uid(entity_type: &str, id: &str) -> Result<EntityUid, CedarError> {
    let entity_type =
        EntityTypeName::from_str(entity_type).map_err(|_| CedarError::InvalidIdentifier)?;
    let id = EntityId::from_str(id).map_err(|_| CedarError::InvalidIdentifier)?;
    Ok(EntityUid::from_type_name_and_id(entity_type, id))
}

fn entities(
    evaluation: &AccessEvaluation,
    principal: &EntityUid,
    resource: &EntityUid,
    schema: Option<&Schema>,
    trusted_entities: &Entities,
) -> Result<Entities, CedarError> {
    if !evaluation.action().attributes().is_empty() {
        return Err(CedarError::InvalidEntity);
    }
    let principal_attributes = match evaluation.subject() {
        SubjectV1::Anonymous => Map::new(),
        SubjectV1::Authenticated(subject) => {
            let mut attributes = attributes_to_json(subject.attributes())?;
            attributes.insert("wasi_issuer".to_owned(), json!(subject.issuer().as_str()));
            attributes.insert(
                "wasi_scopes".to_owned(),
                json!(
                    subject
                        .scopes()
                        .iter()
                        .map(|scope| scope.as_str())
                        .collect::<Vec<_>>()
                ),
            );
            if let Some(tenant_id) = subject.tenant_id() {
                attributes.insert("wasi_tenant_id".to_owned(), json!(tenant_id.as_str()));
            }
            attributes
        }
        _ => return Err(CedarError::InvalidRequest),
    };
    let principal_parents = trusted_entities
        .ancestors(principal)
        .map(Iterator::collect::<Vec<_>>)
        .unwrap_or_default();
    let resource_parents = trusted_entities
        .ancestors(resource)
        .map(Iterator::collect::<Vec<_>>)
        .unwrap_or_default();
    let dynamic = json!([
        entity_json(principal, principal_attributes, principal_parents),
        entity_json(
            resource,
            attributes_to_json(evaluation.resource().attributes())?,
            resource_parents,
        ),
    ]);
    let dynamic =
        Entities::from_json_value(dynamic, schema).map_err(|_| CedarError::InvalidEntity)?;
    trusted_entities
        .clone()
        .upsert_entities(dynamic.iter().cloned(), schema)
        .map_err(|_| CedarError::InvalidEntity)
}

fn entity_json(uid: &EntityUid, attributes: Map<String, Value>, parents: Vec<&EntityUid>) -> Value {
    let id: &str = uid.id().as_ref();
    let parents = parents
        .into_iter()
        .map(|parent| {
            let parent_id: &str = parent.id().as_ref();
            json!({
                "__entity": {
                    "type": parent.type_name().to_string(),
                    "id": parent_id,
                }
            })
        })
        .collect::<Vec<_>>();
    json!({
        "uid": { "type": uid.type_name().to_string(), "id": id },
        "attrs": attributes,
        "parents": parents
    })
}

fn request_context(
    evaluation: &AccessEvaluation,
    action: &EntityUid,
    schema: Option<&Schema>,
) -> Result<Context, CedarError> {
    let attributes = evaluation
        .context()
        .map(|context| attributes_to_json(context.attributes()))
        .transpose()?
        .unwrap_or_default();
    Context::from_json_value(
        Value::Object(attributes),
        schema.map(|schema| (schema, action)),
    )
    .map_err(|_| CedarError::InvalidEntity)
}

fn attributes_to_json(attributes: &AttributesV1) -> Result<Map<String, Value>, CedarError> {
    let mut result = Map::new();
    for attribute in attributes.as_slice() {
        let name = attribute.name().as_str();
        if !is_cedar_identifier(name) || name.starts_with("wasi_") {
            return Err(CedarError::InvalidIdentifier);
        }
        result.insert(
            name.to_owned(),
            json!({
                "value": attribute_value(attribute.value())?,
                "provenance": provenance(attribute.provenance()),
            }),
        );
    }
    Ok(result)
}

fn attribute_value(value: &AttributeValueV1) -> Result<Value, CedarError> {
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
        _ => return Err(CedarError::InvalidEntity),
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

fn is_cedar_identifier(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes
        .next()
        .is_some_and(|byte| byte.is_ascii_alphabetic() || byte == b'_')
        && bytes.all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasi_authz_contract::{
        AccessEvaluation, Action, AttributeNameV1, AttributeStringListV1, AttributeStringV1,
        AttributeV1, AuthenticatedSubjectV1, ContextV1, EntityIdV1, EntityTypeV1, IssuerV1,
        Resource, SubjectV1, TenantIdV1,
    };
    use wasi_authz_testkit::run_core_conformance;

    const CONFORMANCE_POLICY: &str = r#"
        permit(
            principal is user,
            action == Action::"document.read",
            resource == document::"report-1"
        );
    "#;

    #[test]
    fn cedar_provider_passes_shared_conformance() {
        let provider = CedarProvider::new_unvalidated_for_test(
            CONFORMANCE_POLICY,
            "[]",
            "policy-1",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");

        let result = block_on(run_core_conformance(&provider));

        assert!(result.is_ok(), "conformance failed: {result:?}");
        assert!(
            provider
                .capabilities()
                .contains(&ProviderCapability::AttributeProvenance)
        );
    }

    #[test]
    fn cedar_can_explicitly_allow_anonymous_public_resources() {
        let provider = CedarProvider::new_unvalidated_for_test(
            r#"permit(principal is Anonymous, action == Action::"page.view", resource is page);"#,
            "[]",
            "policy-public-1",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");
        let public = AccessEvaluation::new(
            SubjectV1::Anonymous,
            Action::new("page.view").expect("valid fixture"),
            Resource::new("page", "home").expect("valid fixture"),
        );

        let decision = provider
            .evaluate_sync(&public)
            .expect("Cedar evaluates anonymous policy");

        assert!(decision.is_allowed());
    }

    #[test]
    fn provider_debug_redacts_policy_and_trusted_entities() {
        let provider = CedarProvider::new_unvalidated_for_test(
            r#"permit(principal, action, resource == document::"policy-secret");"#,
            r#"[{"uid":{"type":"document","id":"entity-secret"},"attrs":{},"parents":[]}]"#,
            "revision-secret",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");

        let debug = format!("{provider:?}");

        assert!(!debug.contains("policy-secret"));
        assert!(!debug.contains("entity-secret"));
        assert!(!debug.contains("revision-secret"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn embedded_cedar_rejects_foreign_freshness_tokens() {
        let provider = CedarProvider::new_unvalidated_for_test(
            CONFORMANCE_POLICY,
            "[]",
            "policy-1",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");
        let evaluation = wasi_authz_testkit::authenticated_request(
            wasi_authz_contract::ActionNameV1::new("document.read").expect("valid fixture"),
        )
        .with_context(
            wasi_authz_contract::ContextV1::new().with_consistency(
                ConsistencyRequirementV1::AtLeastAsFresh {
                    token: wasi_authz_contract::ConsistencyTokenV1::new("spicedb-token")
                        .expect("valid fixture"),
                },
            ),
        );

        let result = provider.evaluate_sync(&evaluation);

        assert_eq!(result, Err(CedarError::UnsupportedConsistency));
        assert!(
            !provider
                .capabilities()
                .contains(&ProviderCapability::AtLeastAsFreshConsistency)
        );
    }

    #[test]
    fn cedar_enforces_rbac_and_abac_attributes() {
        let policy = r#"
            permit(principal is user, action == Action::"document.read", resource is document)
            when {
                principal in Role::"employee" &&
                principal.roles.value.contains("reader") &&
                principal.roles.provenance == "identity_provider" &&
                resource.classification.value == "internal" &&
                resource.classification.provenance == "resource_store"
            };
        "#;
        let roles = AttributeV1::new(
            AttributeNameV1::new("roles").expect("valid fixture"),
            AttributeValueV1::StringList(
                AttributeStringListV1::new(vec![
                    AttributeStringV1::new("reader").expect("valid fixture"),
                ])
                .expect("valid fixture"),
            ),
            AttributeProvenanceV1::IdentityProvider,
        )
        .expect("valid fixture");
        let classification = AttributeV1::new(
            AttributeNameV1::new("classification").expect("valid fixture"),
            AttributeValueV1::String(AttributeStringV1::new("internal").expect("valid fixture")),
            AttributeProvenanceV1::ResourceStore,
        )
        .expect("valid fixture");
        let subject = AuthenticatedSubjectV1::new(
            EntityTypeV1::new("user").expect("valid fixture"),
            EntityIdV1::new("alice").expect("valid fixture"),
            IssuerV1::new("https://identity.example").expect("valid fixture"),
        )
        .with_attributes(
            AttributesV1::try_from_vec(vec![roles]).expect("valid subject attributes"),
        );
        let principal_id = canonical_principal_id(&subject);
        let trusted_entities = format!(
            r#"[
                {{"uid":{{"type":"user","id":"{principal_id}"}},"attrs":{{}},"parents":[{{"type":"Role","id":"reader"}}]}},
                {{"uid":{{"type":"Role","id":"reader"}},"attrs":{{}},"parents":[{{"type":"Role","id":"employee"}}]}},
                {{"uid":{{"type":"Role","id":"employee"}},"attrs":{{}},"parents":[]}}
            ]"#
        );
        let provider = CedarProvider::new_unvalidated_for_test(
            policy,
            &trusted_entities,
            "policy-rbac-abac-1",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");
        let resource = Resource::new("document", "report-1")
            .expect("valid fixture")
            .with_attributes(
                AttributesV1::try_from_vec(vec![classification])
                    .expect("valid resource attributes"),
            );
        let evaluation = AccessEvaluation::new(
            SubjectV1::Authenticated(subject),
            Action::new("document.read").expect("valid fixture"),
            resource,
        );

        let decision = provider
            .evaluate_sync(&evaluation)
            .expect("Cedar evaluates fixture");

        assert!(decision.is_allowed());
    }

    #[test]
    fn canonical_identity_is_issuer_scoped() {
        let first = fixture_subject("https://issuer-one.example", AttributesV1::new());
        let second = fixture_subject("https://issuer-two.example", AttributesV1::new());

        assert_ne!(
            canonical_principal_id(&first),
            canonical_principal_id(&second)
        );
    }

    #[test]
    fn separation_of_duty_parent_graph_denies() {
        let subject = fixture_subject("https://identity.example", AttributesV1::new());
        let principal_id = canonical_principal_id(&subject);
        let trusted_entities = format!(
            r#"[
                {{"uid":{{"type":"user","id":"{principal_id}"}},"attrs":{{}},"parents":[{{"type":"Role","id":"requester"}},{{"type":"Role","id":"approver"}}]}},
                {{"uid":{{"type":"Role","id":"requester"}},"attrs":{{}},"parents":[]}},
                {{"uid":{{"type":"Role","id":"approver"}},"attrs":{{}},"parents":[]}}
            ]"#
        );
        let policy = r#"
            permit(principal is user, action == Action::"document.approve", resource is document);
            forbid(principal, action == Action::"document.approve", resource)
            when { principal in Role::"requester" && principal in Role::"approver" };
        "#;
        let provider = CedarProvider::new_unvalidated_for_test(
            policy,
            &trusted_entities,
            "policy-sod-1",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");
        let evaluation = AccessEvaluation::new(
            SubjectV1::Authenticated(subject),
            Action::new("document.approve").expect("valid fixture"),
            Resource::new("document", "report-1").expect("valid fixture"),
        );

        let decision = provider
            .evaluate_sync(&evaluation)
            .expect("Cedar evaluates fixture");

        assert!(!decision.is_allowed());
    }

    #[test]
    fn tenant_isolated_roles_do_not_cross_tenants() {
        let role = string_attribute("role", "reader", AttributeProvenanceV1::IdentityProvider);
        let subject = fixture_subject("https://identity.example", attributes([role]))
            .with_tenant_id(TenantIdV1::new("acme").expect("valid fixture"));
        let policy = r#"
            permit(principal is user, action == Action::"document.read", resource is document)
            when {
                principal.role.value == "reader" &&
                principal.role.provenance == "identity_provider" &&
                principal.wasi_tenant_id == resource.tenant.value &&
                resource.tenant.provenance == "resource_store"
            };
        "#;
        let provider = CedarProvider::new_unvalidated_for_test(
            policy,
            "[]",
            "policy-tenant-1",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");
        let same_tenant = AccessEvaluation::new(
            SubjectV1::Authenticated(subject.clone()),
            Action::new("document.read").expect("valid fixture"),
            Resource::new("document", "acme-report")
                .expect("valid fixture")
                .with_attributes(attributes([string_attribute(
                    "tenant",
                    "acme",
                    AttributeProvenanceV1::ResourceStore,
                )])),
        );
        let other_tenant = AccessEvaluation::new(
            SubjectV1::Authenticated(subject),
            Action::new("document.read").expect("valid fixture"),
            Resource::new("document", "globex-report")
                .expect("valid fixture")
                .with_attributes(attributes([string_attribute(
                    "tenant",
                    "globex",
                    AttributeProvenanceV1::ResourceStore,
                )])),
        );

        assert!(
            provider
                .evaluate_sync(&same_tenant)
                .expect("Cedar evaluates")
                .is_allowed()
        );
        assert!(
            provider
                .evaluate_sync(&other_tenant)
                .expect("Cedar evaluates")
                .is_denied()
        );
    }

    #[test]
    fn dynamic_separation_of_duty_uses_trusted_request_and_resource_context() {
        let role = string_attribute("role", "approver", AttributeProvenanceV1::IdentityProvider);
        let subject = fixture_subject("https://identity.example", attributes([role]));
        let provider = CedarProvider::new_unvalidated_for_test(
            r#"
                permit(principal is user, action == Action::"document.approve", resource is document)
                when {
                    principal.role.value == "approver" &&
                    principal.role.provenance == "identity_provider" &&
                    context.actor_id.provenance == "gateway" &&
                    resource.requester_id.provenance == "resource_store" &&
                    context.actor_id.value != resource.requester_id.value
                };
            "#,
            "[]",
            "policy-dynamic-sod-1",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");
        let request = |requester_id: &str| {
            AccessEvaluation::new(
                SubjectV1::Authenticated(subject.clone()),
                Action::new("document.approve").expect("valid fixture"),
                Resource::new("document", "report-1")
                    .expect("valid fixture")
                    .with_attributes(attributes([string_attribute(
                        "requester_id",
                        requester_id,
                        AttributeProvenanceV1::ResourceStore,
                    )])),
            )
            .with_context(ContextV1::new().with_attributes(attributes([
                string_attribute("actor_id", "alice", AttributeProvenanceV1::Gateway),
            ])))
        };

        assert!(
            provider
                .evaluate_sync(&request("bob"))
                .expect("Cedar evaluates")
                .is_allowed()
        );
        assert!(
            provider
                .evaluate_sync(&request("alice"))
                .expect("Cedar evaluates")
                .is_denied()
        );
    }

    #[test]
    fn department_clearance_classification_and_time_all_gate_abac() {
        let subject = fixture_subject(
            "https://identity.example",
            attributes([
                string_attribute(
                    "department",
                    "finance",
                    AttributeProvenanceV1::IdentityProvider,
                ),
                integer_attribute("clearance", 3, AttributeProvenanceV1::IdentityProvider),
            ]),
        );
        let provider = CedarProvider::new_unvalidated_for_test(
            r#"
                permit(principal is user, action == Action::"document.read", resource is document)
                when {
                    principal.department.value == resource.department.value &&
                    principal.department.provenance == "identity_provider" &&
                    resource.department.provenance == "resource_store" &&
                    principal.clearance.value >= resource.classification.value &&
                    principal.clearance.provenance == "identity_provider" &&
                    resource.classification.provenance == "resource_store" &&
                    context.hour.value >= 9 && context.hour.value < 17 &&
                    context.hour.provenance == "gateway"
                };
            "#,
            "[]",
            "policy-abac-1",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");
        let request = |department: &str, classification: i64, hour: i64| {
            AccessEvaluation::new(
                SubjectV1::Authenticated(subject.clone()),
                Action::new("document.read").expect("valid fixture"),
                Resource::new("document", "report-1")
                    .expect("valid fixture")
                    .with_attributes(attributes([
                        string_attribute(
                            "department",
                            department,
                            AttributeProvenanceV1::ResourceStore,
                        ),
                        integer_attribute(
                            "classification",
                            classification,
                            AttributeProvenanceV1::ResourceStore,
                        ),
                    ])),
            )
            .with_context(ContextV1::new().with_attributes(attributes([
                integer_attribute("hour", hour, AttributeProvenanceV1::Gateway),
            ])))
        };

        assert!(
            provider
                .evaluate_sync(&request("finance", 3, 10))
                .expect("Cedar evaluates")
                .is_allowed()
        );
        for denied in [
            request("legal", 3, 10),
            request("finance", 4, 10),
            request("finance", 3, 18),
        ] {
            assert!(
                provider
                    .evaluate_sync(&denied)
                    .expect("Cedar evaluates")
                    .is_denied()
            );
        }
    }

    #[test]
    fn activation_failures_are_typed_and_fail_closed() {
        assert!(matches!(
            CedarProvider::new_validated(
                CONFORMANCE_POLICY,
                "not-json",
                "[]",
                "policy-1",
                "cedar-4.11.2"
            ),
            Err(CedarError::InvalidSchema)
        ));
        assert!(matches!(
            CedarProvider::new_unvalidated_for_test(
                "this is not Cedar",
                "[]",
                "policy-1",
                "cedar-4.11.2"
            ),
            Err(CedarError::InvalidPolicy)
        ));
        let schema = r#"{
            "": {
                "entityTypes": {
                    "user": {"shape": {"type": "Record", "attributes": {}}},
                    "document": {"shape": {"type": "Record", "attributes": {}}}
                },
                "actions": {
                    "document.read": {"appliesTo": {
                        "principalTypes": ["user"],
                        "resourceTypes": ["document"],
                        "context": {"type": "Record", "attributes": {}}
                    }}
                }
            }
        }"#;
        assert!(matches!(
            CedarProvider::new_validated(
                r#"permit(principal, action == Action::"document.delete", resource);"#,
                schema,
                "[]",
                "policy-1",
                "cedar-4.11.2"
            ),
            Err(CedarError::PolicyValidation)
        ));
    }

    #[test]
    fn missing_policy_attribute_is_indeterminate() {
        let provider = CedarProvider::new_unvalidated_for_test(
            r#"permit(principal is user, action == Action::"document.read", resource) when { principal.roles.value.contains("reader") };"#,
            "[]",
            "policy-missing-1",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");
        let evaluation = AccessEvaluation::new(
            SubjectV1::Authenticated(fixture_subject(
                "https://identity.example",
                AttributesV1::new(),
            )),
            Action::new("document.read").expect("valid fixture"),
            Resource::new("document", "report-1").expect("valid fixture"),
        );

        let result = provider.evaluate_sync(&evaluation);

        assert_eq!(result, Err(CedarError::Indeterminate));
    }

    #[test]
    fn wrong_provenance_denies_without_becoming_indeterminate() {
        let role = AttributeV1::new(
            AttributeNameV1::new("role").expect("valid fixture"),
            AttributeValueV1::String(AttributeStringV1::new("reader").expect("valid fixture")),
            AttributeProvenanceV1::Application,
        )
        .expect("valid fixture");
        let subject = fixture_subject(
            "https://identity.example",
            AttributesV1::try_from_vec(vec![role]).expect("valid fixture"),
        );
        let provider = CedarProvider::new_unvalidated_for_test(
            r#"permit(principal is user, action == Action::"document.read", resource) when { principal.role.value == "reader" && principal.role.provenance == "identity_provider" };"#,
            "[]",
            "policy-provenance-1",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");
        let evaluation = AccessEvaluation::new(
            SubjectV1::Authenticated(subject),
            Action::new("document.read").expect("valid fixture"),
            Resource::new("document", "report-1").expect("valid fixture"),
        );

        let decision = provider
            .evaluate_sync(&evaluation)
            .expect("Cedar evaluates fixture");

        assert!(!decision.is_allowed());
    }

    #[test]
    fn wrong_attribute_type_is_indeterminate() {
        let clearance = AttributeV1::new(
            AttributeNameV1::new("clearance").expect("valid fixture"),
            AttributeValueV1::String(AttributeStringV1::new("3").expect("valid fixture")),
            AttributeProvenanceV1::IdentityProvider,
        )
        .expect("valid fixture");
        let subject = fixture_subject(
            "https://identity.example",
            AttributesV1::try_from_vec(vec![clearance]).expect("valid fixture"),
        );
        let provider = CedarProvider::new_unvalidated_for_test(
            r#"permit(principal is user, action == Action::"document.read", resource) when { principal.clearance.value >= 3 };"#,
            "[]",
            "policy-type-1",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");
        let evaluation = AccessEvaluation::new(
            SubjectV1::Authenticated(subject),
            Action::new("document.read").expect("valid fixture"),
            Resource::new("document", "report-1").expect("valid fixture"),
        );

        let result = provider.evaluate_sync(&evaluation);

        assert_eq!(result, Err(CedarError::Indeterminate));
    }

    #[test]
    fn stale_resource_attribute_denies() {
        let version = AttributeV1::new(
            AttributeNameV1::new("version").expect("valid fixture"),
            AttributeValueV1::Integer(1),
            AttributeProvenanceV1::ResourceStore,
        )
        .expect("valid fixture");
        let resource = Resource::new("document", "report-1")
            .expect("valid fixture")
            .with_attributes(AttributesV1::try_from_vec(vec![version]).expect("valid fixture"));
        let provider = CedarProvider::new_unvalidated_for_test(
            r#"permit(principal is user, action == Action::"document.read", resource) when { resource.version.value >= 2 && resource.version.provenance == "resource_store" };"#,
            "[]",
            "policy-version-2",
            "cedar-4.11.2",
        )
        .expect("valid Cedar fixture");
        let evaluation = AccessEvaluation::new(
            SubjectV1::Authenticated(fixture_subject(
                "https://identity.example",
                AttributesV1::new(),
            )),
            Action::new("document.read").expect("valid fixture"),
            resource,
        );

        let decision = provider
            .evaluate_sync(&evaluation)
            .expect("Cedar evaluates fixture");

        assert!(!decision.is_allowed());
    }

    #[test]
    fn strict_schema_and_policy_activate_together() {
        let schema = r#"{
            "": {
                "entityTypes": {
                    "user": {"shape": {"type": "Record", "attributes": {
                        "wasi_issuer": {"type": "String", "required": true},
                        "wasi_scopes": {"type": "Set", "element": {"type": "String"}, "required": true}
                    }}},
                    "document": {"shape": {"type": "Record", "attributes": {}}}
                },
                "actions": {
                    "document.read": {"appliesTo": {
                        "principalTypes": ["user"],
                        "resourceTypes": ["document"],
                        "context": {"type": "Record", "attributes": {}}
                    }}
                }
            }
        }"#;
        let provider = CedarProvider::new_validated(
            r#"permit(principal is user, action == Action::"document.read", resource is document);"#,
            schema,
            "[]",
            "policy-schema-1",
            "cedar-4.11.2",
        )
        .expect("schema and policy validate");
        let evaluation = AccessEvaluation::new(
            SubjectV1::Authenticated(fixture_subject(
                "https://identity.example",
                AttributesV1::new(),
            )),
            Action::new("document.read").expect("valid fixture"),
            Resource::new("document", "report-1").expect("valid fixture"),
        );

        let decision = provider
            .evaluate_sync(&evaluation)
            .expect("validated Cedar evaluates");

        assert!(decision.is_allowed());
    }

    fn fixture_subject(issuer: &str, attributes: AttributesV1) -> AuthenticatedSubjectV1 {
        AuthenticatedSubjectV1::new(
            EntityTypeV1::new("user").expect("valid fixture"),
            EntityIdV1::new("alice").expect("valid fixture"),
            IssuerV1::new(issuer).expect("valid fixture"),
        )
        .with_attributes(attributes)
    }

    fn attributes<const N: usize>(values: [AttributeV1; N]) -> AttributesV1 {
        AttributesV1::try_from_vec(Vec::from(values)).expect("valid fixture attributes")
    }

    fn string_attribute(name: &str, value: &str, provenance: AttributeProvenanceV1) -> AttributeV1 {
        AttributeV1::new(
            AttributeNameV1::new(name).expect("valid fixture"),
            AttributeValueV1::String(AttributeStringV1::new(value).expect("valid fixture")),
            provenance,
        )
        .expect("valid fixture")
    }

    fn integer_attribute(name: &str, value: i64, provenance: AttributeProvenanceV1) -> AttributeV1 {
        AttributeV1::new(
            AttributeNameV1::new(name).expect("valid fixture"),
            AttributeValueV1::Integer(value),
            provenance,
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
