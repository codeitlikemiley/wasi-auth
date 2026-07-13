//! Embedded Cedar authorization provider.

use std::fmt;
use std::str::FromStr as _;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use cedar_policy::{
    Authorizer as CedarAuthorizer, Context, Decision as CedarDecision, Entities, EntityId,
    EntityTypeName, EntityUid, PolicySet, Request, Schema, ValidationMode, Validator,
};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::authorization::{
    AccessRequest, ConsistencyRequirement, Decision, DecisionProvider, ProviderCapabilities,
};
use crate::context::{AuthenticationAssurance, ContextError, PolicyRevision};

/// Default bounded application-permission policy used by the fullstack
/// template and native trusted ingress.
pub const DEFAULT_APPLICATION_POLICY: &str = include_str!("cedar/default_application.cedar");

/// Strict Cedar schema paired with [`DEFAULT_APPLICATION_POLICY`].
pub const DEFAULT_APPLICATION_SCHEMA: &str = include_str!("cedar/default_application_schema.json");

/// Revision identifier for the immutable application policy embedded in the
/// library, native ingress, and generated fullstack application.
pub const DEFAULT_APPLICATION_POLICY_REVISION: &str = "embedded-v1";

/// Cedar policy activation or evaluation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum CedarError {
    /// Policy source was syntactically invalid.
    #[error("invalid Cedar policy set")]
    InvalidPolicy,
    /// Schema source was invalid.
    #[error("invalid Cedar schema")]
    InvalidSchema,
    /// Policy validation against the schema failed.
    #[error("Cedar policy validation failed")]
    PolicyValidation,
    /// Trusted entity data was invalid.
    #[error("invalid Cedar entity data")]
    InvalidEntity,
    /// An action, resource, or principal was not representable in Cedar.
    #[error("authorization input is not representable in Cedar")]
    InvalidIdentifier,
    /// Cedar rejected the typed request.
    #[error("invalid Cedar authorization request")]
    InvalidRequest,
    /// Policy evaluation produced diagnostics and is therefore indeterminate.
    #[error("Cedar authorization evaluation was indeterminate")]
    Indeterminate,
    /// Embedded policy cannot satisfy an external at-least-as-fresh token.
    #[error("Cedar does not support the requested consistency mode")]
    UnsupportedConsistency,
    /// Policy metadata violated the bounded context contract.
    #[error("invalid Cedar policy revision")]
    InvalidMetadata,
}

/// Parsed embedded Cedar policy and trusted entity graph.
#[derive(Clone)]
pub struct CedarProvider {
    policies: PolicySet,
    schema: Option<Schema>,
    trusted_entities: Entities,
    policy_revision: PolicyRevision,
}

impl fmt::Debug for CedarProvider {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("CedarProvider")
            .field("policies", &"[REDACTED]")
            .field("schema_configured", &self.schema.is_some())
            .field("trusted_entities", &"[REDACTED]")
            .field("policy_revision", &"[REDACTED]")
            .finish()
    }
}

impl CedarProvider {
    /// Loads a policy bundle whose exact source was strictly validated during
    /// the artifact build or policy-publication transaction.
    ///
    /// This constructor deliberately omits runtime schema parsing and policy
    /// validation. It is intended for immutable embedded bundles in
    /// short-lived component instances; dynamic or user-supplied policy must
    /// use [`Self::new_validated`]. Evaluation diagnostics still fail closed.
    ///
    /// # Errors
    ///
    /// Returns [`CedarError`] for invalid policy, entity, or revision data.
    pub fn new_prevalidated(
        policy_source: &str,
        trusted_entities_json: &str,
        policy_revision: impl Into<String>,
    ) -> Result<Self, CedarError> {
        let policies = PolicySet::from_str(policy_source).map_err(|_| CedarError::InvalidPolicy)?;
        let trusted_entities = Entities::from_json_str(trusted_entities_json, None)
            .map_err(|_| CedarError::InvalidEntity)?;
        Ok(Self {
            policies,
            schema: None,
            trusted_entities,
            policy_revision: PolicyRevision::new(policy_revision)
                .map_err(|_| CedarError::InvalidMetadata)?,
        })
    }

    /// Parses policies and entities without schema validation for tests.
    ///
    /// # Errors
    ///
    /// Returns [`CedarError`] for invalid policy, entity, or revision data.
    pub fn new_unvalidated_for_test(
        policy_source: &str,
        trusted_entities_json: &str,
        policy_revision: impl Into<String>,
    ) -> Result<Self, CedarError> {
        Self::new_prevalidated(policy_source, trusted_entities_json, policy_revision)
    }

    /// Parses a schema, strictly validates policies, and loads trusted entities.
    ///
    /// # Errors
    ///
    /// Returns [`CedarError`] when parsing or strict validation fails.
    pub fn new_validated(
        policy_source: &str,
        schema_source: &str,
        trusted_entities_json: &str,
        policy_revision: impl Into<String>,
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
            policy_revision: PolicyRevision::new(policy_revision)
                .map_err(|_| CedarError::InvalidMetadata)?,
        })
    }

    /// Evaluates one request synchronously in-process.
    ///
    /// # Errors
    ///
    /// Returns [`CedarError`] for conversion, unsupported consistency, or an
    /// indeterminate policy result. Callers must fail closed on every error.
    pub fn check_sync(&self, request: &AccessRequest) -> Result<Decision, CedarError> {
        if matches!(
            request.consistency(),
            ConsistencyRequirement::AtLeastAsFresh { .. }
        ) {
            return Err(CedarError::UnsupportedConsistency);
        }
        let principal = uid("User", &canonical_principal_id(request))?;
        let action = uid("Action", request.action().as_str())?;
        let resource = uid(
            request.resource().resource_type().as_str(),
            request.resource().id(),
        )?;
        let entities = self.entities(request, &principal, &resource)?;
        let context = Context::from_json_value(
            request_context_json(request),
            self.schema.as_ref().map(|schema| (schema, &action)),
        )
        .map_err(|_| CedarError::InvalidEntity)?;
        let cedar_request =
            Request::new(principal, action, resource, context, self.schema.as_ref())
                .map_err(|_| CedarError::InvalidRequest)?;
        let response =
            CedarAuthorizer::new().is_authorized(&cedar_request, &self.policies, &entities);
        if response.diagnostics().errors().next().is_some() {
            return Err(CedarError::Indeterminate);
        }
        Ok(if response.decision() == CedarDecision::Allow {
            Decision::allow(self.policy_revision.clone(), "cedar.allow")
        } else {
            Decision::deny(self.policy_revision.clone(), "cedar.deny")
        })
    }

    fn entities(
        &self,
        request: &AccessRequest,
        principal: &EntityUid,
        resource: &EntityUid,
    ) -> Result<Entities, CedarError> {
        let mut principal_attributes = Map::new();
        principal_attributes.insert(
            "wasi_issuer".to_owned(),
            json!(request.context().principal().issuer()),
        );
        principal_attributes.insert(
            "wasi_assurance".to_owned(),
            json!(match request.context().assurance() {
                AuthenticationAssurance::Aal1 => "aal1",
                AuthenticationAssurance::Aal2 => "aal2",
            }),
        );
        principal_attributes.insert(
            "wasi_system_administrator".to_owned(),
            json!(request.context().principal().is_system_administrator()),
        );
        principal_attributes.insert(
            "wasi_permissions".to_owned(),
            json!(
                request
                    .authorization()
                    .map(|snapshot| snapshot.permissions().collect::<Vec<_>>())
                    .unwrap_or_default()
            ),
        );
        if let Some(organization_id) = request.context().organization_id() {
            principal_attributes.insert(
                "wasi_organization_id".to_owned(),
                json!(organization_id.as_str()),
            );
        }
        let mut resource_attributes = Map::new();
        if let Some(organization_id) = request.resource().organization_id() {
            resource_attributes.insert(
                "wasi_organization_id".to_owned(),
                json!(organization_id.as_str()),
            );
        }
        let principal_parents = ancestors(&self.trusted_entities, principal);
        let resource_parents = ancestors(&self.trusted_entities, resource);
        let dynamic = json!([
            entity_json(principal, principal_attributes, principal_parents),
            entity_json(resource, resource_attributes, resource_parents),
        ]);
        let dynamic = Entities::from_json_value(dynamic, self.schema.as_ref())
            .map_err(|_| CedarError::InvalidEntity)?;
        self.trusted_entities
            .clone()
            .upsert_entities(dynamic.iter().cloned(), self.schema.as_ref())
            .map_err(|_| CedarError::InvalidEntity)
    }
}

impl DecisionProvider for CedarProvider {
    type Error = CedarError;

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            batch_check: true,
            list_resources: false,
            consistency_tokens: false,
        }
    }

    fn check<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> impl Future<Output = Result<Decision, Self::Error>> + Send + 'a {
        std::future::ready(self.check_sync(request))
    }

    fn batch_check<'a>(
        &'a self,
        requests: &'a [AccessRequest],
    ) -> impl Future<Output = Result<Vec<Decision>, Self::Error>> + Send + 'a {
        std::future::ready(
            requests
                .iter()
                .map(|request| self.check_sync(request))
                .collect(),
        )
    }
}

/// Returns the stable issuer-scoped Cedar principal identifier.
#[must_use]
pub fn canonical_principal_id(request: &AccessRequest) -> String {
    let principal = request.context().principal();
    let mut identity =
        Vec::with_capacity(principal.issuer().len() + principal.user_id().as_str().len() + 1);
    identity.extend_from_slice(principal.issuer().as_bytes());
    identity.push(0);
    identity.extend_from_slice(principal.user_id().as_str().as_bytes());
    format!("v1_{}", URL_SAFE_NO_PAD.encode(identity))
}

fn uid(entity_type: &str, id: &str) -> Result<EntityUid, CedarError> {
    let entity_type =
        EntityTypeName::from_str(entity_type).map_err(|_| CedarError::InvalidIdentifier)?;
    let id = EntityId::from_str(id).map_err(|_| CedarError::InvalidIdentifier)?;
    Ok(EntityUid::from_type_name_and_id(entity_type, id))
}

fn ancestors<'a>(entities: &'a Entities, uid: &EntityUid) -> Vec<&'a EntityUid> {
    entities
        .ancestors(uid)
        .map(Iterator::collect)
        .unwrap_or_default()
}

fn entity_json(uid: &EntityUid, attrs: Map<String, Value>, parents: Vec<&EntityUid>) -> Value {
    let id: &str = uid.id().as_ref();
    let parents = parents
        .into_iter()
        .map(|parent| {
            let parent_id: &str = parent.id().as_ref();
            json!({"__entity": {"type": parent.type_name().to_string(), "id": parent_id}})
        })
        .collect::<Vec<_>>();
    json!({
        "uid": {"type": uid.type_name().to_string(), "id": id},
        "attrs": attrs,
        "parents": parents,
    })
}

fn request_context_json(request: &AccessRequest) -> Value {
    let mut context = request
        .attributes()
        .iter()
        .map(|(name, value)| (name.clone(), json!(value)))
        .collect::<Map<_, _>>();
    if let Some(organization_id) = request.context().organization_id() {
        context.insert(
            "wasi_organization_id".to_owned(),
            json!(organization_id.as_str()),
        );
    }
    Value::Object(context)
}

impl From<ContextError> for CedarError {
    fn from(_: ContextError) -> Self {
        Self::InvalidMetadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authorization::{ActionName, Resource, ResourceType};
    use crate::context::AuthorizationSnapshot;
    use crate::testkit::VerifiedAuthContextBuilder;

    #[test]
    fn permit_policy_allows_request() {
        let provider = CedarProvider::new_unvalidated_for_test(
            "permit(principal, action, resource);",
            "[]",
            "policy-one",
        )
        .expect("valid fixture");
        let context = VerifiedAuthContextBuilder::new()
            .build()
            .expect("valid fixture");
        let resource = Resource::new(
            ResourceType::new("Document").expect("valid fixture"),
            "document-one",
            context.organization_id().cloned(),
        )
        .expect("valid fixture");
        let request = AccessRequest::new(
            context,
            ActionName::new("document.read").expect("valid fixture"),
            resource,
        )
        .expect("valid fixture");

        let decision = provider.check_sync(&request).expect("policy evaluates");

        assert!(decision.is_allowed());
    }

    #[test]
    fn default_application_bundle_passes_strict_validation() {
        CedarProvider::new_validated(
            DEFAULT_APPLICATION_POLICY,
            DEFAULT_APPLICATION_SCHEMA,
            "[]",
            DEFAULT_APPLICATION_POLICY_REVISION,
        )
        .expect("default application policy must remain strictly valid");
    }

    #[test]
    fn validated_policy_uses_server_loaded_permission_set() {
        let provider = CedarProvider::new_validated(
            r#"permit(principal is User, action == Action::"authorization.check", resource is Document)
                when { principal.wasi_permissions.contains(context.requested_action) };"#,
            r#"{
              "": {
                "entityTypes": {
                  "User": {"shape": {"type": "Record", "attributes": {
                    "wasi_issuer": {"type": "String", "required": true},
                    "wasi_assurance": {"type": "String", "required": true},
                    "wasi_system_administrator": {"type": "Boolean", "required": true},
                    "wasi_permissions": {"type": "Set", "element": {"type": "String"}, "required": true},
                    "wasi_organization_id": {"type": "String", "required": false}
                  }}},
                  "Document": {"shape": {"type": "Record", "attributes": {
                    "wasi_organization_id": {"type": "String", "required": false}
                  }}}
                },
                "actions": {
                  "authorization.check": {"appliesTo": {
                    "principalTypes": ["User"],
                    "resourceTypes": ["Document"],
                    "context": {"type": "Record", "attributes": {
                      "requested_action": {"type": "String", "required": true},
                      "wasi_organization_id": {"type": "String", "required": false}
                    }}
                  }}
                }
              }
            }"#,
            "[]",
            "policy-one",
        )
        .expect("valid policy");
        let context = VerifiedAuthContextBuilder::new()
            .build()
            .expect("valid fixture");
        let resource = Resource::new(
            ResourceType::new("Document").expect("valid fixture"),
            "document-one",
            context.organization_id().cloned(),
        )
        .expect("valid fixture");
        let request = AccessRequest::new(
            context,
            ActionName::new("authorization.check").expect("valid fixture"),
            resource,
        )
        .expect("valid fixture")
        .with_authorization_snapshot(
            AuthorizationSnapshot::new(["document.read"], [], None, None).expect("valid fixture"),
        )
        .with_attribute("requested_action", "document.read")
        .expect("valid fixture");

        let decision = provider.check_sync(&request).expect("policy evaluates");

        assert!(decision.is_allowed());
    }
}
