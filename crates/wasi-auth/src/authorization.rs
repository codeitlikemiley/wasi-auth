//! Runtime-neutral authorization contracts and static-dispatch enforcement.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::future::Future;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::context::{AuthorizationSnapshot, OrganizationId, PolicyRevision, VerifiedAuthContext};

/// Maximum number of checks accepted by one batch operation.
pub const MAX_BATCH_CHECKS: usize = 100;
const MAX_NAME_BYTES: usize = 128;
const MAX_RESOURCE_ID_BYTES: usize = 512;
const MAX_ATTRIBUTES: usize = 64;
const MAX_ATTRIBUTE_VALUE_BYTES: usize = 2_048;

/// Validation failure for an authorization request.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum AuthorizationRequestError {
    /// An action or resource name was invalid.
    #[error("authorization name is invalid")]
    InvalidName,
    /// A resource identifier was invalid.
    #[error("authorization resource identifier is invalid")]
    InvalidResourceId,
    /// The protected resource belongs to a different tenant.
    #[error("authorization tenant does not match the verified context")]
    TenantMismatch,
    /// Too many contextual attributes were supplied.
    #[error("authorization request has too many attributes")]
    TooManyAttributes,
    /// An attribute name or value exceeded the bounded contract.
    #[error("authorization attribute is invalid")]
    InvalidAttribute,
}

/// Validated application action name such as `member.invite`.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ActionName(String);

impl ActionName {
    /// Validates an action name.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationRequestError::InvalidName`] for an empty,
    /// oversized, or non-canonical value.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthorizationRequestError> {
        let value = value.into();
        validate_name(&value)?;
        Ok(Self(value))
    }

    /// Returns the validated action name.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Validated resource type such as `Organization` or `Counter`.
#[derive(Clone, Debug, Deserialize, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct ResourceType(String);

impl ResourceType {
    /// Validates a resource type.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationRequestError::InvalidName`] for an invalid value.
    pub fn new(value: impl Into<String>) -> Result<Self, AuthorizationRequestError> {
        let value = value.into();
        validate_name(&value)?;
        Ok(Self(value))
    }

    /// Returns the validated resource type.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Protected application resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct Resource {
    resource_type: ResourceType,
    id: String,
    organization_id: Option<OrganizationId>,
}

impl Resource {
    /// Constructs a bounded resource reference.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationRequestError`] when the type or identifier is
    /// invalid.
    pub fn new(
        resource_type: ResourceType,
        id: impl Into<String>,
        organization_id: Option<OrganizationId>,
    ) -> Result<Self, AuthorizationRequestError> {
        let id = id.into();
        if id.is_empty()
            || id.len() > MAX_RESOURCE_ID_BYTES
            || id.chars().any(|character| character.is_control())
        {
            return Err(AuthorizationRequestError::InvalidResourceId);
        }
        Ok(Self {
            resource_type,
            id,
            organization_id,
        })
    }

    /// Returns the resource type.
    #[must_use]
    pub const fn resource_type(&self) -> &ResourceType {
        &self.resource_type
    }

    /// Returns the resource identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Returns the owning organization for a tenant resource.
    #[must_use]
    pub const fn organization_id(&self) -> Option<&OrganizationId> {
        self.organization_id.as_ref()
    }
}

/// Consistency requirement for an authorization decision.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum ConsistencyRequirement {
    /// Prefer the lowest-latency decision supported by the provider.
    #[default]
    MinimizeLatency,
    /// Evaluate against a fully consistent provider snapshot.
    FullyConsistent,
    /// Evaluate at least as fresh as the supplied provider token.
    AtLeastAsFresh {
        /// Opaque provider consistency token.
        token: String,
    },
}

/// One bounded authorization evaluation.
#[derive(Clone, Debug)]
pub struct AccessRequest {
    context: VerifiedAuthContext,
    action: ActionName,
    resource: Resource,
    consistency: ConsistencyRequirement,
    attributes: BTreeMap<String, String>,
    authorization: Option<AuthorizationSnapshot>,
}

impl AccessRequest {
    /// Constructs a request and enforces the verified tenant boundary.
    ///
    /// System administrators may target an explicit tenant for administrative
    /// recovery. Every other principal must have the same organization in the
    /// verified context and protected resource.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationRequestError::TenantMismatch`] on a cross-tenant
    /// request.
    pub fn new(
        context: VerifiedAuthContext,
        action: ActionName,
        resource: Resource,
    ) -> Result<Self, AuthorizationRequestError> {
        if !context.principal().is_system_administrator()
            && resource.organization_id() != context.organization_id()
        {
            return Err(AuthorizationRequestError::TenantMismatch);
        }
        Ok(Self {
            context,
            action,
            resource,
            consistency: ConsistencyRequirement::default(),
            attributes: BTreeMap::new(),
            authorization: None,
        })
    }

    /// Attaches current authorization facts loaded from authoritative storage.
    #[must_use]
    pub fn with_authorization_snapshot(mut self, snapshot: AuthorizationSnapshot) -> Self {
        self.authorization = Some(snapshot);
        self
    }

    /// Sets the provider consistency requirement.
    #[must_use]
    pub fn with_consistency(mut self, consistency: ConsistencyRequirement) -> Self {
        self.consistency = consistency;
        self
    }

    /// Adds one bounded application attribute.
    ///
    /// # Errors
    ///
    /// Returns [`AuthorizationRequestError`] when the map exceeds its bounds or
    /// the name/value is invalid.
    pub fn with_attribute(
        mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<Self, AuthorizationRequestError> {
        if self.attributes.len() >= MAX_ATTRIBUTES {
            return Err(AuthorizationRequestError::TooManyAttributes);
        }
        let name = name.into();
        let value = value.into();
        validate_name(&name).map_err(|_| AuthorizationRequestError::InvalidAttribute)?;
        if value.len() > MAX_ATTRIBUTE_VALUE_BYTES || value.chars().any(char::is_control) {
            return Err(AuthorizationRequestError::InvalidAttribute);
        }
        self.attributes.insert(name, value);
        Ok(self)
    }

    /// Returns the trusted authentication context.
    #[must_use]
    pub const fn context(&self) -> &VerifiedAuthContext {
        &self.context
    }

    /// Returns the requested action.
    #[must_use]
    pub const fn action(&self) -> &ActionName {
        &self.action
    }

    /// Returns the protected resource.
    #[must_use]
    pub const fn resource(&self) -> &Resource {
        &self.resource
    }

    /// Returns the consistency requirement.
    #[must_use]
    pub const fn consistency(&self) -> &ConsistencyRequirement {
        &self.consistency
    }

    /// Returns trusted application attributes.
    #[must_use]
    pub const fn attributes(&self) -> &BTreeMap<String, String> {
        &self.attributes
    }

    /// Returns current server-loaded authorization facts, when supplied.
    #[must_use]
    pub const fn authorization(&self) -> Option<&AuthorizationSnapshot> {
        self.authorization.as_ref()
    }
}

/// Provider capability declaration used for startup validation.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ProviderCapabilities {
    /// Whether the provider has an optimized batch implementation.
    pub batch_check: bool,
    /// Whether the provider can enumerate authorized resources.
    pub list_resources: bool,
    /// Whether the provider supports at-least-as-fresh consistency tokens.
    pub consistency_tokens: bool,
}

/// Authorization result with bounded provider metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Decision {
    allowed: bool,
    reason: &'static str,
    policy_revision: PolicyRevision,
    consistency_token: Option<String>,
}

impl Decision {
    /// Constructs an allow decision.
    #[must_use]
    pub fn allow(policy_revision: PolicyRevision, reason: &'static str) -> Self {
        Self {
            allowed: true,
            reason,
            policy_revision,
            consistency_token: None,
        }
    }

    /// Constructs a deny decision.
    #[must_use]
    pub fn deny(policy_revision: PolicyRevision, reason: &'static str) -> Self {
        Self {
            allowed: false,
            reason,
            policy_revision,
            consistency_token: None,
        }
    }

    /// Attaches an opaque provider consistency token.
    #[must_use]
    pub fn with_consistency_token(mut self, token: impl Into<String>) -> Self {
        self.consistency_token = Some(token.into());
        self
    }

    /// Returns whether access is allowed.
    #[must_use]
    pub const fn is_allowed(&self) -> bool {
        self.allowed
    }

    /// Returns the stable provider reason code.
    #[must_use]
    pub const fn reason(&self) -> &'static str {
        self.reason
    }

    /// Returns the policy revision used for the decision.
    #[must_use]
    pub const fn policy_revision(&self) -> &PolicyRevision {
        &self.policy_revision
    }

    /// Returns the provider consistency token, when present.
    #[must_use]
    pub fn consistency_token(&self) -> Option<&str> {
        self.consistency_token.as_deref()
    }
}

/// Static-dispatch authorization provider.
pub trait DecisionProvider: Sync {
    /// Provider-specific failure. Callers must fail closed on every error.
    type Error: StdError + Send + Sync + 'static;

    /// Returns capabilities used to validate application configuration.
    fn capabilities(&self) -> ProviderCapabilities;

    /// Evaluates one request without allocating a trait object on the hot path.
    fn check<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> impl Future<Output = Result<Decision, Self::Error>> + Send + 'a;

    /// Evaluates a provider-native batch when available.
    ///
    /// The default preserves compatibility by evaluating requests in order.
    /// Providers advertising `batch_check` must override this method with one
    /// provider operation or an equivalent optimized local evaluation.
    fn batch_check<'a>(
        &'a self,
        requests: &'a [AccessRequest],
    ) -> impl Future<Output = Result<Vec<Decision>, Self::Error>> + Send + 'a {
        async move {
            let mut decisions = Vec::with_capacity(requests.len());
            for request in requests {
                decisions.push(self.check(request).await?);
            }
            Ok(decisions)
        }
    }
}

impl<P> DecisionProvider for &P
where
    P: DecisionProvider + ?Sized,
{
    type Error = P::Error;

    fn capabilities(&self) -> ProviderCapabilities {
        (*self).capabilities()
    }

    fn check<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> impl Future<Output = Result<Decision, Self::Error>> + Send + 'a {
        (*self).check(request)
    }

    fn batch_check<'a>(
        &'a self,
        requests: &'a [AccessRequest],
    ) -> impl Future<Output = Result<Vec<Decision>, Self::Error>> + Send + 'a {
        (*self).batch_check(requests)
    }
}

/// Batch authorization failure.
#[derive(Debug, Error)]
pub enum BatchAuthorizationError<E>
where
    E: StdError + Send + Sync + 'static,
{
    /// The caller exceeded [`MAX_BATCH_CHECKS`].
    #[error("authorization batch exceeds the maximum of {MAX_BATCH_CHECKS}")]
    TooManyRequests,
    /// The provider returned an indeterminate failure.
    #[error("authorization provider failed")]
    Provider(#[source] E),
}

/// Thin static-dispatch policy enforcement facade.
#[derive(Clone, Debug)]
pub struct Authorizer<P> {
    provider: P,
}

impl<P> Authorizer<P>
where
    P: DecisionProvider,
{
    /// Wraps a concrete decision provider.
    #[must_use]
    pub const fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Returns startup capabilities for the concrete provider.
    #[must_use]
    pub fn capabilities(&self) -> ProviderCapabilities {
        self.provider.capabilities()
    }

    /// Evaluates one request.
    ///
    /// # Errors
    ///
    /// Returns the concrete provider failure. The application must map it to a
    /// fail-closed response.
    pub async fn check(&self, request: &AccessRequest) -> Result<Decision, P::Error> {
        self.provider.check(request).await
    }

    /// Evaluates a bounded batch using the concrete provider implementation.
    ///
    /// # Errors
    ///
    /// Returns [`BatchAuthorizationError`] for oversized batches or a provider
    /// failure.
    pub async fn batch_check(
        &self,
        requests: &[AccessRequest],
    ) -> Result<Vec<Decision>, BatchAuthorizationError<P::Error>> {
        if requests.len() > MAX_BATCH_CHECKS {
            return Err(BatchAuthorizationError::TooManyRequests);
        }
        self.provider
            .batch_check(requests)
            .await
            .map_err(BatchAuthorizationError::Provider)
    }

    /// Returns a shared reference to the concrete provider.
    #[must_use]
    pub const fn provider(&self) -> &P {
        &self.provider
    }
}

fn validate_name(value: &str) -> Result<(), AuthorizationRequestError> {
    if value.is_empty()
        || value.len() > MAX_NAME_BYTES
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-' | b':'))
    {
        return Err(AuthorizationRequestError::InvalidName);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkit::VerifiedAuthContextBuilder;

    #[test]
    fn access_request_rejects_cross_tenant_resource() {
        let context = VerifiedAuthContextBuilder::new()
            .organization_id("organization-one")
            .build()
            .expect("valid fixture");
        let resource = Resource::new(
            ResourceType::new("Document").expect("valid fixture"),
            "document-one",
            Some(OrganizationId::new("organization-two").expect("valid fixture")),
        )
        .expect("valid fixture");

        let result = AccessRequest::new(
            context,
            ActionName::new("document.read").expect("valid fixture"),
            resource,
        );

        assert!(matches!(
            result,
            Err(AuthorizationRequestError::TenantMismatch)
        ));
    }
}
