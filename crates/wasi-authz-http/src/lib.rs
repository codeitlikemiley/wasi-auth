//! Coarse HTTP policy enforcement point (PEP) helpers.
//!
//! Route configuration supplies stable domain actions and resource IDs. Raw
//! URLs, query strings, headers, and bodies are deliberately not converted
//! into authorization attributes by this crate.

#![deny(rustdoc::broken_intra_doc_links)]

use http::header::{CACHE_CONTROL, CONTENT_LENGTH, WWW_AUTHENTICATE};
use http::{Response, StatusCode};
use wasi_authz_client::DecisionProvider;
use wasi_authz_contract::{
    AccessEvaluation, Action, AttributeNameV1, AttributeProvenanceV1, AttributeStringListV1,
    AttributeStringV1, AttributeV1, AttributeValueV1, AttributesV1, AuthenticatedSubjectV1,
    ContextV1, ContractError, DecisionResponseV1, EntityIdV1, EntityTypeV1, IssuerV1, RequestIdV1,
    Resource, ScopeV1, SubjectV1, TenantIdV1,
};
use wasi_http_metadata::{AuthContextV1, AuthStateV1, PrincipalV1};
use wasi_http_policy_core::normalize_policy_path;

/// Failure while converting a trusted authentication boundary into a coarse
/// authorization evaluation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum BoundaryError {
    /// The context was minted for a different immutable terminal service.
    ServiceMismatch,
    /// Trusted identity fields could not fit the bounded authorization profile.
    InvalidIdentity,
    /// The HTTP method or normalized path was invalid or oversized.
    InvalidRequestMetadata,
}

impl std::fmt::Display for BoundaryError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("invalid trusted authorization boundary")
    }
}

impl std::error::Error for BoundaryError {}

/// Builds the fixed coarse HTTP authorization evaluation.
///
/// The action is always `http.request`; the resource is always `service` with
/// the immutable configured service ID. Only the method and normalized,
/// query-free path enter contextual attributes. Bodies, cookies, authorization
/// headers, raw query strings, and session identifiers are never included.
///
/// # Errors
///
/// Returns [`BoundaryError`] for service mismatch, invalid identity metadata,
/// or ambiguous request paths.
pub fn coarse_http_evaluation(
    auth_context: &AuthContextV1,
    expected_service_id: &str,
    method: &str,
    path_with_query: &str,
    request_id: Option<&str>,
) -> Result<AccessEvaluation, BoundaryError> {
    let subject = subject_from_auth_context(auth_context, expected_service_id)?;
    let method = http::Method::from_bytes(method.as_bytes())
        .map_err(|_| BoundaryError::InvalidRequestMetadata)?
        .as_str()
        .to_ascii_uppercase();
    if method.len() > 32 {
        return Err(BoundaryError::InvalidRequestMetadata);
    }
    let path = normalize_policy_path(path_with_query)
        .map_err(|_| BoundaryError::InvalidRequestMetadata)?;
    let attributes = AttributesV1::try_from_vec(vec![
        string_attribute("http_method", &method, AttributeProvenanceV1::Gateway)?,
        string_attribute("http_path", &path, AttributeProvenanceV1::Gateway)?,
    ])
    .map_err(|_| BoundaryError::InvalidRequestMetadata)?;
    let mut context = ContextV1::new().with_attributes(attributes);
    if let Some(request_id) = request_id {
        context = context.with_request_id(
            RequestIdV1::new(request_id).map_err(|_| BoundaryError::InvalidRequestMetadata)?,
        );
    }
    Ok(AccessEvaluation::new(
        subject,
        Action::new("http.request").map_err(|_| BoundaryError::InvalidRequestMetadata)?,
        Resource::new("service", expected_service_id)
            .map_err(|_| BoundaryError::InvalidRequestMetadata)?,
    )
    .with_context(context))
}

/// Converts a canonical authentication context into the bounded authorization
/// subject used by HTTP and Leptos integrations.
///
/// Session IDs and authentication decision IDs are intentionally excluded.
///
/// # Errors
///
/// Returns [`BoundaryError`] for service mismatch or invalid identity fields.
pub fn subject_from_auth_context(
    auth_context: &AuthContextV1,
    expected_service_id: &str,
) -> Result<SubjectV1, BoundaryError> {
    if auth_context.service_id() != expected_service_id {
        return Err(BoundaryError::ServiceMismatch);
    }
    Ok(match (auth_context.state(), auth_context.principal()) {
        (AuthStateV1::Anonymous, None) => SubjectV1::Anonymous,
        (AuthStateV1::Authenticated, Some(principal)) => {
            SubjectV1::Authenticated(authenticated_subject(principal)?)
        }
        _ => return Err(BoundaryError::InvalidIdentity),
    })
}

fn authenticated_subject(principal: &PrincipalV1) -> Result<AuthenticatedSubjectV1, BoundaryError> {
    let mut subject = AuthenticatedSubjectV1::new(
        EntityTypeV1::new("principal").map_err(|_| BoundaryError::InvalidIdentity)?,
        EntityIdV1::new(principal.subject()).map_err(|_| BoundaryError::InvalidIdentity)?,
        IssuerV1::new(principal.issuer()).map_err(|_| BoundaryError::InvalidIdentity)?,
    );
    if let Some(tenant_id) = principal.tenant_id() {
        subject = subject.with_tenant_id(
            TenantIdV1::new(tenant_id).map_err(|_| BoundaryError::InvalidIdentity)?,
        );
    }
    let scopes = principal
        .scopes()
        .iter()
        .map(|scope| ScopeV1::new(scope).map_err(|_| BoundaryError::InvalidIdentity))
        .collect::<Result<Vec<_>, _>>()?;
    subject = subject
        .with_scopes(scopes)
        .map_err(|_| BoundaryError::InvalidIdentity)?;

    let mut attributes = Vec::new();
    if !principal.roles().is_empty() {
        attributes.push(string_list_attribute(
            "roles",
            principal.roles(),
            AttributeProvenanceV1::IdentityProvider,
        )?);
    }
    if let Some(acr) = principal.acr() {
        attributes.push(string_attribute(
            "acr",
            acr,
            AttributeProvenanceV1::IdentityProvider,
        )?);
    }
    if !principal.amr().is_empty() {
        attributes.push(string_list_attribute(
            "amr",
            principal.amr(),
            AttributeProvenanceV1::IdentityProvider,
        )?);
    }
    if let Some(actor) = principal.actor() {
        attributes.push(string_attribute(
            "actor_issuer",
            actor.issuer(),
            AttributeProvenanceV1::IdentityProvider,
        )?);
        attributes.push(string_attribute(
            "actor_subject",
            actor.subject(),
            AttributeProvenanceV1::IdentityProvider,
        )?);
    }
    if let Some(auth_time) = principal.auth_time() {
        attributes.push(integer_attribute("auth_time", auth_time)?);
    }
    if let Some(expires_at) = principal.expires_at() {
        attributes.push(integer_attribute("expires_at", expires_at)?);
    }
    subject = subject.with_attributes(
        AttributesV1::try_from_vec(attributes).map_err(|_| BoundaryError::InvalidIdentity)?,
    );
    Ok(subject)
}

fn string_attribute(
    name: &str,
    value: &str,
    provenance: AttributeProvenanceV1,
) -> Result<AttributeV1, BoundaryError> {
    AttributeV1::new(
        AttributeNameV1::new(name).map_err(|_| BoundaryError::InvalidIdentity)?,
        AttributeValueV1::String(
            AttributeStringV1::new(value).map_err(|_| BoundaryError::InvalidIdentity)?,
        ),
        provenance,
    )
    .map_err(|_| BoundaryError::InvalidIdentity)
}

fn string_list_attribute(
    name: &str,
    values: &[String],
    provenance: AttributeProvenanceV1,
) -> Result<AttributeV1, BoundaryError> {
    let values = values
        .iter()
        .map(|value| AttributeStringV1::new(value).map_err(|_| BoundaryError::InvalidIdentity))
        .collect::<Result<Vec<_>, _>>()?;
    AttributeV1::new(
        AttributeNameV1::new(name).map_err(|_| BoundaryError::InvalidIdentity)?,
        AttributeValueV1::StringList(
            AttributeStringListV1::new(values).map_err(|_| BoundaryError::InvalidIdentity)?,
        ),
        provenance,
    )
    .map_err(|_| BoundaryError::InvalidIdentity)
}

fn integer_attribute(name: &str, value: u64) -> Result<AttributeV1, BoundaryError> {
    AttributeV1::new(
        AttributeNameV1::new(name).map_err(|_| BoundaryError::InvalidIdentity)?,
        AttributeValueV1::Integer(
            value
                .try_into()
                .map_err(|_| BoundaryError::InvalidIdentity)?,
        ),
        AttributeProvenanceV1::IdentityProvider,
    )
    .map_err(|_| BoundaryError::InvalidIdentity)
}

/// Stable coarse route authorization requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteAuthorization {
    action: Action,
    resource: Resource,
    context: Option<ContextV1>,
}

impl RouteAuthorization {
    /// Validates a route action and typed resource.
    ///
    /// # Errors
    ///
    /// Returns a contract error for an invalid action, resource type, or ID.
    pub fn new(
        action: impl Into<String>,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Result<Self, ContractError> {
        Ok(Self::from_parts(
            Action::new(action)?,
            Resource::new(resource_type, resource_id)?,
        ))
    }

    /// Constructs a route requirement from validated parts.
    pub fn from_parts(action: Action, resource: Resource) -> Self {
        Self {
            action,
            resource,
            context: None,
        }
    }

    /// Adds bounded trusted request context.
    pub fn with_context(mut self, context: ContextV1) -> Self {
        self.context = Some(context);
        self
    }

    /// Returns the stable domain action.
    pub fn action(&self) -> &Action {
        &self.action
    }

    /// Returns the typed resource.
    pub fn resource(&self) -> &Resource {
        &self.resource
    }

    fn evaluation(&self, subject: SubjectV1) -> AccessEvaluation {
        let evaluation = AccessEvaluation::new(subject, self.action.clone(), self.resource.clone());
        match &self.context {
            Some(context) => evaluation.with_context(context.clone()),
            None => evaluation,
        }
    }
}

/// Result of enforcing one HTTP route requirement.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum PepOutcome {
    /// The provider returned one explicit valid allow decision.
    Allow(DecisionResponseV1),
    /// The request must stop at the PEP.
    Reject(HttpRejection),
}

impl PepOutcome {
    /// Returns whether downstream handling may proceed.
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow(_))
    }
}

/// Fail-closed HTTP rejection classification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum HttpRejection {
    /// No authenticated principal was present for a denied operation.
    AuthenticationRequired,
    /// An authenticated principal was denied.
    Forbidden,
    /// No trustworthy provider decision was available.
    ProviderUnavailable,
}

impl HttpRejection {
    /// Returns the stable HTTP status mapping.
    pub fn status(self) -> StatusCode {
        match self {
            Self::AuthenticationRequired => StatusCode::UNAUTHORIZED,
            Self::Forbidden => StatusCode::FORBIDDEN,
            Self::ProviderUnavailable => StatusCode::SERVICE_UNAVAILABLE,
        }
    }

    /// Creates an empty non-cacheable rejection response.
    ///
    /// No provider error detail or policy input is exposed to the client.
    pub fn into_response(self) -> Response<Vec<u8>> {
        let mut response = Response::new(Vec::new());
        *response.status_mut() = self.status();
        response
            .headers_mut()
            .insert(CACHE_CONTROL, http::HeaderValue::from_static("no-store"));
        response
            .headers_mut()
            .insert(CONTENT_LENGTH, http::HeaderValue::from_static("0"));
        if self == Self::AuthenticationRequired {
            response
                .headers_mut()
                .insert(WWW_AUTHENTICATE, http::HeaderValue::from_static("Bearer"));
        }
        response
    }
}

/// Coarse route PEP backed by a shared decision provider.
#[derive(Clone, Debug)]
pub struct HttpEnforcer<P> {
    provider: P,
}

impl<P> HttpEnforcer<P>
where
    P: DecisionProvider,
{
    /// Constructs an enforcer.
    pub fn new(provider: P) -> Self {
        Self { provider }
    }

    /// Evaluates and maps one route policy fail closed.
    ///
    /// Provider and decoding errors always become 503. A valid deny becomes
    /// 401 for an anonymous subject and 403 for an authenticated subject.
    pub async fn enforce(
        &self,
        subject: SubjectV1,
        authorization: &RouteAuthorization,
    ) -> PepOutcome {
        let authenticated = subject.is_authenticated();
        let evaluation = authorization.evaluation(subject);
        match self.provider.evaluate(&evaluation).await {
            Ok(decision) if decision.is_allowed() => PepOutcome::Allow(decision),
            Ok(_) if authenticated => PepOutcome::Reject(HttpRejection::Forbidden),
            Ok(_) => PepOutcome::Reject(HttpRejection::AuthenticationRequired),
            Err(_) => PepOutcome::Reject(HttpRejection::ProviderUnavailable),
        }
    }

    /// Returns the configured provider.
    pub fn provider(&self) -> &P {
        &self.provider
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wasi_authz_contract::{AuthenticatedSubjectV1, EntityIdV1, EntityTypeV1, IssuerV1};
    use wasi_authz_testkit::MockProvider;
    use wasi_http_metadata::{AuthContextV1, PrincipalV1};

    #[test]
    fn authenticated_deny_maps_to_403() {
        let subject = SubjectV1::Authenticated(AuthenticatedSubjectV1::new(
            EntityTypeV1::new("user").expect("valid fixture"),
            EntityIdV1::new("alice").expect("valid fixture"),
            IssuerV1::new("https://identity.example").expect("valid fixture"),
        ));
        let requirement = RouteAuthorization::new("document.delete", "document", "report-1")
            .expect("valid fixture");

        let outcome = block_on(HttpEnforcer::new(MockProvider).enforce(subject, &requirement));

        assert_eq!(outcome, PepOutcome::Reject(HttpRejection::Forbidden));
    }

    #[test]
    fn anonymous_deny_maps_to_401() {
        let requirement = RouteAuthorization::new("document.read", "document", "report-1")
            .expect("valid fixture");

        let outcome =
            block_on(HttpEnforcer::new(MockProvider).enforce(SubjectV1::Anonymous, &requirement));

        assert_eq!(
            outcome,
            PepOutcome::Reject(HttpRejection::AuthenticationRequired)
        );
        let response = HttpRejection::AuthenticationRequired.into_response();
        assert_eq!(
            response.headers().get(WWW_AUTHENTICATE),
            Some(&http::HeaderValue::from_static("Bearer"))
        );
    }

    #[test]
    fn allowed_route_can_continue() {
        let subject = SubjectV1::Authenticated(AuthenticatedSubjectV1::new(
            EntityTypeV1::new("user").expect("valid fixture"),
            EntityIdV1::new("alice").expect("valid fixture"),
            IssuerV1::new("https://identity.example").expect("valid fixture"),
        ));
        let requirement = RouteAuthorization::new("document.read", "document", "report-1")
            .expect("valid fixture");

        let outcome = block_on(HttpEnforcer::new(MockProvider).enforce(subject, &requirement));

        assert!(outcome.is_allowed());
    }

    #[test]
    fn coarse_evaluation_is_service_bound_and_query_free() {
        let principal = PrincipalV1::new("https://identity.example", "alice")
            .expect("valid fixture")
            .with_roles(["reader"])
            .expect("valid fixture")
            .with_session_id(Some("must-not-cross-authz-boundary"))
            .expect("valid fixture");
        let context = AuthContextV1::authenticated(
            "orders-api",
            ["orders-api"],
            principal,
            "authn-decision-1",
            "authn-policy-1",
        )
        .expect("valid fixture");

        let evaluation = coarse_http_evaluation(
            &context,
            "orders-api",
            "M-SEARCH",
            "/%61dmin/report?token=must-not-cross",
            Some("request-1"),
        )
        .expect("trusted boundary converts");
        let encoded = String::from_utf8(evaluation.to_json_vec().expect("evaluation encodes"))
            .expect("JSON is UTF-8");

        assert_eq!(evaluation.action().name().as_str(), "http.request");
        assert_eq!(evaluation.resource().resource_type().as_str(), "service");
        assert_eq!(evaluation.resource().id().as_str(), "orders-api");
        assert!(encoded.contains("/admin/report"));
        assert!(!encoded.contains("must-not-cross"));
    }

    #[test]
    fn coarse_evaluation_rejects_service_mismatch() {
        let context =
            AuthContextV1::anonymous("orders-api", ["orders-api"]).expect("valid fixture");

        let result = coarse_http_evaluation(&context, "billing-api", "GET", "/", None);

        assert_eq!(result, Err(BoundaryError::ServiceMismatch));
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
