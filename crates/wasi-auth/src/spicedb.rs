//! Direct SpiceDB CheckPermission provider with no AuthZEN service hop.

use std::collections::BTreeMap;
use std::error::Error as StdError;
use std::fmt;
use std::future::Future;

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use http::header::{ACCEPT, AUTHORIZATION, CONTENT_LENGTH, CONTENT_TYPE};
use http::{Request, Response, StatusCode, Uri};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use thiserror::Error;

use crate::authentication::{RelationshipOperation, RelationshipOutboxIntent};
use crate::authorization::{
    AccessRequest, ConsistencyRequirement, Decision, DecisionProvider, ProviderCapabilities,
};
use crate::context::{ContextError, PolicyRevision};

const MAX_DOCUMENT_BYTES: usize = 256 * 1024;

/// Outbound HTTP transport implemented by the selected WASI runtime.
pub trait SpiceDbTransport: Sync {
    /// Transport-specific failure.
    type Error: StdError + Send + Sync + 'static;

    /// Sends one bounded CheckPermission request.
    fn send<'a>(
        &'a self,
        request: Request<Vec<u8>>,
    ) -> impl Future<Output = Result<Response<Vec<u8>>, Self::Error>> + Send + 'a;
}

/// Validated SpiceDB CheckPermission endpoint.
#[derive(Clone)]
pub struct SpiceDbEndpoint(Uri);

impl SpiceDbEndpoint {
    /// Parses an HTTPS or loopback HTTP CheckPermission endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SpiceDbConfigurationError::InvalidEndpoint`] for unsafe or
    /// malformed endpoints.
    pub fn new(value: &str) -> Result<Self, SpiceDbConfigurationError> {
        let uri = value
            .parse::<Uri>()
            .map_err(|_| SpiceDbConfigurationError::InvalidEndpoint)?;
        let scheme = uri
            .scheme_str()
            .ok_or(SpiceDbConfigurationError::InvalidEndpoint)?;
        let host = uri
            .host()
            .ok_or(SpiceDbConfigurationError::InvalidEndpoint)?;
        let secure = scheme == "https";
        let loopback = scheme == "http" && matches!(host, "localhost" | "127.0.0.1" | "[::1]");
        if (!secure && !loopback) || uri.path() != "/v1/permissions/check" {
            return Err(SpiceDbConfigurationError::InvalidEndpoint);
        }
        Ok(Self(uri))
    }

    /// Returns the validated endpoint URI.
    #[must_use]
    pub const fn as_uri(&self) -> &Uri {
        &self.0
    }
}

impl fmt::Debug for SpiceDbEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SpiceDbEndpoint([REDACTED])")
    }
}

/// Secret provider credential with redacted debug output.
#[derive(Clone)]
pub struct SpiceDbBearerToken(String);

impl SpiceDbBearerToken {
    /// Validates a non-empty bearer token.
    ///
    /// # Errors
    ///
    /// Returns [`SpiceDbConfigurationError::InvalidToken`] for empty, oversized,
    /// or control-character-containing input.
    pub fn new(value: impl Into<String>) -> Result<Self, SpiceDbConfigurationError> {
        let value = value.into();
        if value.is_empty() || value.len() > 4_096 || value.chars().any(char::is_control) {
            return Err(SpiceDbConfigurationError::InvalidToken);
        }
        Ok(Self(value))
    }
}

impl fmt::Debug for SpiceDbBearerToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SpiceDbBearerToken([REDACTED])")
    }
}

/// Validated action-to-SpiceDB-permission mapping.
#[derive(Clone, Debug)]
pub struct PermissionMap(BTreeMap<String, String>);

impl PermissionMap {
    /// Constructs a non-empty map of canonical action and permission names.
    ///
    /// # Errors
    ///
    /// Returns [`SpiceDbConfigurationError::InvalidPermissionMap`] for invalid
    /// entries.
    pub fn new(
        entries: impl IntoIterator<Item = (impl Into<String>, impl Into<String>)>,
    ) -> Result<Self, SpiceDbConfigurationError> {
        let entries = entries
            .into_iter()
            .map(|(action, permission)| (action.into(), permission.into()))
            .collect::<BTreeMap<_, _>>();
        if entries.is_empty()
            || entries.iter().any(|(action, permission)| {
                action.is_empty()
                    || action.len() > 128
                    || !is_spicedb_name(permission)
                    || action.chars().any(char::is_control)
            })
        {
            return Err(SpiceDbConfigurationError::InvalidPermissionMap);
        }
        Ok(Self(entries))
    }

    fn permission_for(&self, action: &str) -> Result<&str, SpiceDbError> {
        self.0
            .get(action)
            .map(String::as_str)
            .ok_or(SpiceDbError::UnmappedAction)
    }
}

/// SpiceDB provider configuration failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum SpiceDbConfigurationError {
    /// Endpoint was malformed or unsafe.
    #[error("invalid SpiceDB CheckPermission endpoint")]
    InvalidEndpoint,
    /// Provider token was malformed.
    #[error("invalid SpiceDB bearer token")]
    InvalidToken,
    /// Action-to-permission mapping was invalid.
    #[error("invalid SpiceDB permission map")]
    InvalidPermissionMap,
    /// Policy revision violated the bounded metadata contract.
    #[error("invalid SpiceDB policy revision")]
    InvalidPolicyRevision,
}

/// Direct SpiceDB decision failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum SpiceDbError {
    /// No permission mapping exists for the requested action.
    #[error("authorization action has no SpiceDB permission mapping")]
    UnmappedAction,
    /// Subject, resource, context, or request body was not representable.
    #[error("authorization input is not representable in SpiceDB")]
    InvalidRequest,
    /// Outbound host transport failed.
    #[error("SpiceDB transport failed")]
    Transport(#[source] Box<dyn StdError + Send + Sync>),
    /// Provider rejected authentication.
    #[error("SpiceDB rejected provider authentication")]
    ProviderAuthentication,
    /// Provider was unavailable or returned a non-success status.
    #[error("SpiceDB provider is unavailable")]
    ProviderUnavailable,
    /// Response body or media type violated the bounded contract.
    #[error("invalid SpiceDB CheckPermission response")]
    InvalidResponse,
    /// Permission depends on unresolved caveat inputs.
    #[error("SpiceDB returned a conditional permission")]
    ConditionalPermission,
}

/// Direct static-dispatch SpiceDB provider.
#[derive(Clone)]
pub struct SpiceDbProvider<T> {
    endpoint: SpiceDbEndpoint,
    bearer_token: SpiceDbBearerToken,
    transport: T,
    permissions: PermissionMap,
    policy_revision: PolicyRevision,
}

impl<T> fmt::Debug for SpiceDbProvider<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpiceDbProvider")
            .field("endpoint", &self.endpoint)
            .field("bearer_token", &self.bearer_token)
            .field("transport", &"[REDACTED]")
            .field("permissions", &self.permissions)
            .field("policy_revision", &"[REDACTED]")
            .finish()
    }
}

impl<T> SpiceDbProvider<T>
where
    T: SpiceDbTransport,
{
    /// Constructs a direct provider with explicit mapping and metadata.
    ///
    /// # Errors
    ///
    /// Returns [`SpiceDbConfigurationError`] for an invalid policy revision.
    pub fn new(
        endpoint: SpiceDbEndpoint,
        bearer_token: SpiceDbBearerToken,
        transport: T,
        permissions: PermissionMap,
        policy_revision: impl Into<String>,
    ) -> Result<Self, SpiceDbConfigurationError> {
        Ok(Self {
            endpoint,
            bearer_token,
            transport,
            permissions,
            policy_revision: PolicyRevision::new(policy_revision)
                .map_err(|_| SpiceDbConfigurationError::InvalidPolicyRevision)?,
        })
    }

    async fn check_inner(&self, request: &AccessRequest) -> Result<Decision, SpiceDbError> {
        let resource_type = request.resource().resource_type().as_str();
        let resource_id = request.resource().id();
        if !is_spicedb_name(resource_type) || !is_spicedb_id(resource_id) {
            return Err(SpiceDbError::InvalidRequest);
        }
        let subject_id = canonical_subject_id(request);
        let permission = self.permissions.permission_for(request.action().as_str())?;
        let payload = CheckPermissionRequest {
            consistency: consistency_json(request.consistency()),
            resource: ObjectReference {
                object_type: resource_type,
                object_id: resource_id,
            },
            permission,
            subject: SubjectReference {
                object: ObjectReference {
                    object_type: "user",
                    object_id: &subject_id,
                },
            },
            context: request_context_json(request),
        };
        let body = serde_json::to_vec(&payload).map_err(|_| SpiceDbError::InvalidRequest)?;
        if body.len() > MAX_DOCUMENT_BYTES {
            return Err(SpiceDbError::InvalidRequest);
        }
        let authorization = format!("Bearer {}", self.bearer_token.0);
        let outbound = Request::builder()
            .method(http::Method::POST)
            .uri(self.endpoint.as_uri().clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .header(AUTHORIZATION, authorization)
            .body(body)
            .map_err(|_| SpiceDbError::InvalidRequest)?;
        let response = self
            .transport
            .send(outbound)
            .await
            .map_err(|error| SpiceDbError::Transport(Box::new(error)))?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(SpiceDbError::ProviderAuthentication);
            }
            _ => return Err(SpiceDbError::ProviderUnavailable),
        }
        let media_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if media_type != Some("application/json") || response.body().len() > MAX_DOCUMENT_BYTES {
            return Err(SpiceDbError::InvalidResponse);
        }
        let wire: CheckPermissionResponse =
            serde_json::from_slice(response.body()).map_err(|_| SpiceDbError::InvalidResponse)?;
        if wire.partial_caveat_info.is_some() {
            return Err(SpiceDbError::ConditionalPermission);
        }
        let token = wire.checked_at.ok_or(SpiceDbError::InvalidResponse)?.token;
        match wire.permissionship.as_str() {
            "PERMISSIONSHIP_HAS_PERMISSION" => Ok(Decision::allow(
                self.policy_revision.clone(),
                "spicedb.allow",
            )
            .with_consistency_token(token)),
            "PERMISSIONSHIP_NO_PERMISSION" => {
                Ok(Decision::deny(self.policy_revision.clone(), "spicedb.deny")
                    .with_consistency_token(token))
            }
            "PERMISSIONSHIP_CONDITIONAL_PERMISSION" => Err(SpiceDbError::ConditionalPermission),
            _ => Err(SpiceDbError::InvalidResponse),
        }
    }

    async fn batch_check_inner(
        &self,
        requests: &[AccessRequest],
    ) -> Result<Vec<Decision>, SpiceDbError> {
        let Some(first) = requests.first() else {
            return Ok(Vec::new());
        };
        if requests
            .iter()
            .any(|request| request.consistency() != first.consistency())
        {
            return Err(SpiceDbError::InvalidRequest);
        }
        let items = requests
            .iter()
            .map(|request| {
                let resource_type = request.resource().resource_type().as_str();
                let resource_id = request.resource().id();
                if !is_spicedb_name(resource_type) || !is_spicedb_id(resource_id) {
                    return Err(SpiceDbError::InvalidRequest);
                }
                Ok(CheckBulkPermissionsRequestItem {
                    resource: OwnedObjectReference {
                        object_type: resource_type.to_owned(),
                        object_id: resource_id.to_owned(),
                    },
                    permission: self
                        .permissions
                        .permission_for(request.action().as_str())?
                        .to_owned(),
                    subject: OwnedSubjectReference {
                        object: OwnedObjectReference {
                            object_type: "user".to_owned(),
                            object_id: canonical_subject_id(request),
                        },
                    },
                    context: request_context_json(request),
                })
            })
            .collect::<Result<Vec<_>, SpiceDbError>>()?;
        let body = serde_json::to_vec(&CheckBulkPermissionsRequest {
            consistency: consistency_json(first.consistency()),
            items,
            with_tracing: false,
        })
        .map_err(|_| SpiceDbError::InvalidRequest)?;
        if body.len() > MAX_DOCUMENT_BYTES {
            return Err(SpiceDbError::InvalidRequest);
        }
        let mut parts = self.endpoint.as_uri().clone().into_parts();
        parts.path_and_query = Some(
            "/v1/permissions/checkbulk"
                .parse()
                .map_err(|_| SpiceDbError::InvalidRequest)?,
        );
        let bulk_endpoint = Uri::from_parts(parts).map_err(|_| SpiceDbError::InvalidRequest)?;
        let outbound = Request::builder()
            .method(http::Method::POST)
            .uri(bulk_endpoint)
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .header(AUTHORIZATION, format!("Bearer {}", self.bearer_token.0))
            .body(body)
            .map_err(|_| SpiceDbError::InvalidRequest)?;
        let response = self
            .transport
            .send(outbound)
            .await
            .map_err(|error| SpiceDbError::Transport(Box::new(error)))?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(SpiceDbError::ProviderAuthentication);
            }
            _ => return Err(SpiceDbError::ProviderUnavailable),
        }
        let media_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if media_type != Some("application/json") || response.body().len() > MAX_DOCUMENT_BYTES {
            return Err(SpiceDbError::InvalidResponse);
        }
        let wire: CheckBulkPermissionsResponse =
            serde_json::from_slice(response.body()).map_err(|_| SpiceDbError::InvalidResponse)?;
        if wire.pairs.len() != requests.len() {
            return Err(SpiceDbError::InvalidResponse);
        }
        let token = wire.checked_at.ok_or(SpiceDbError::InvalidResponse)?.token;
        wire.pairs
            .into_iter()
            .map(|pair| {
                if pair.error.is_some() {
                    return Err(SpiceDbError::ProviderUnavailable);
                }
                let item = pair.item.ok_or(SpiceDbError::InvalidResponse)?;
                if item.partial_caveat_info.is_some() {
                    return Err(SpiceDbError::ConditionalPermission);
                }
                match item.permissionship.as_str() {
                    "PERMISSIONSHIP_HAS_PERMISSION" => Ok(Decision::allow(
                        self.policy_revision.clone(),
                        "spicedb.allow",
                    )
                    .with_consistency_token(&token)),
                    "PERMISSIONSHIP_NO_PERMISSION" => {
                        Ok(Decision::deny(self.policy_revision.clone(), "spicedb.deny")
                            .with_consistency_token(&token))
                    }
                    "PERMISSIONSHIP_CONDITIONAL_PERMISSION" => {
                        Err(SpiceDbError::ConditionalPermission)
                    }
                    _ => Err(SpiceDbError::InvalidResponse),
                }
            })
            .collect()
    }
}

impl<T> DecisionProvider for SpiceDbProvider<T>
where
    T: SpiceDbTransport,
{
    type Error = SpiceDbError;

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            batch_check: true,
            list_resources: false,
            consistency_tokens: true,
        }
    }

    fn check<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> impl Future<Output = Result<Decision, Self::Error>> + Send + 'a {
        self.check_inner(request)
    }

    fn batch_check<'a>(
        &'a self,
        requests: &'a [AccessRequest],
    ) -> impl Future<Output = Result<Vec<Decision>, Self::Error>> + Send + 'a {
        self.batch_check_inner(requests)
    }
}

/// Validated SpiceDB WriteRelationships endpoint.
#[derive(Clone)]
pub struct SpiceDbWriteEndpoint(Uri);

impl SpiceDbWriteEndpoint {
    /// Parses an HTTPS or loopback HTTP WriteRelationships endpoint.
    ///
    /// # Errors
    ///
    /// Returns [`SpiceDbConfigurationError::InvalidEndpoint`] for malformed or
    /// unsafe input.
    pub fn new(value: &str) -> Result<Self, SpiceDbConfigurationError> {
        let uri = value
            .parse::<Uri>()
            .map_err(|_| SpiceDbConfigurationError::InvalidEndpoint)?;
        let scheme = uri
            .scheme_str()
            .ok_or(SpiceDbConfigurationError::InvalidEndpoint)?;
        let host = uri
            .host()
            .ok_or(SpiceDbConfigurationError::InvalidEndpoint)?;
        let secure = scheme == "https";
        let loopback = scheme == "http" && matches!(host, "localhost" | "127.0.0.1" | "[::1]");
        if (!secure && !loopback) || uri.path() != "/v1/relationships/write" {
            return Err(SpiceDbConfigurationError::InvalidEndpoint);
        }
        Ok(Self(uri))
    }
}

impl fmt::Debug for SpiceDbWriteEndpoint {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SpiceDbWriteEndpoint([REDACTED])")
    }
}

/// Successful relationship write metadata.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RelationshipWriteReceipt {
    consistency_token: String,
}

impl RelationshipWriteReceipt {
    /// Returns the ZedToken corresponding to the committed relationship write.
    #[must_use]
    pub fn consistency_token(&self) -> &str {
        &self.consistency_token
    }
}

/// Direct, bounded SpiceDB relationship writer for durable outbox workers.
#[derive(Clone)]
pub struct SpiceDbRelationshipWriter<T> {
    endpoint: SpiceDbWriteEndpoint,
    bearer_token: SpiceDbBearerToken,
    transport: T,
}

impl<T> fmt::Debug for SpiceDbRelationshipWriter<T> {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SpiceDbRelationshipWriter")
            .field("endpoint", &self.endpoint)
            .field("bearer_token", &self.bearer_token)
            .field("transport", &"[REDACTED]")
            .finish()
    }
}

impl<T> SpiceDbRelationshipWriter<T>
where
    T: SpiceDbTransport,
{
    /// Constructs a direct relationship writer.
    #[must_use]
    pub const fn new(
        endpoint: SpiceDbWriteEndpoint,
        bearer_token: SpiceDbBearerToken,
        transport: T,
    ) -> Self {
        Self {
            endpoint,
            bearer_token,
            transport,
        }
    }

    /// Commits between one and 100 relationship intents in one provider call.
    ///
    /// # Errors
    ///
    /// Returns [`SpiceDbError::InvalidRequest`] for malformed or oversized
    /// intents and fails closed for provider/transport errors.
    pub async fn write(
        &self,
        intents: &[RelationshipOutboxIntent],
    ) -> Result<RelationshipWriteReceipt, SpiceDbError> {
        if intents.is_empty() || intents.len() > 100 {
            return Err(SpiceDbError::InvalidRequest);
        }
        let updates = intents
            .iter()
            .map(relationship_update)
            .collect::<Result<Vec<_>, _>>()?;
        let body = serde_json::to_vec(&WriteRelationshipsRequest { updates })
            .map_err(|_| SpiceDbError::InvalidRequest)?;
        if body.len() > MAX_DOCUMENT_BYTES {
            return Err(SpiceDbError::InvalidRequest);
        }
        let authorization = format!("Bearer {}", self.bearer_token.0);
        let request = Request::builder()
            .method(http::Method::POST)
            .uri(self.endpoint.0.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json")
            .header(CONTENT_LENGTH, body.len())
            .header(AUTHORIZATION, authorization)
            .body(body)
            .map_err(|_| SpiceDbError::InvalidRequest)?;
        let response = self
            .transport
            .send(request)
            .await
            .map_err(|error| SpiceDbError::Transport(Box::new(error)))?;
        match response.status() {
            StatusCode::OK => {}
            StatusCode::UNAUTHORIZED | StatusCode::FORBIDDEN => {
                return Err(SpiceDbError::ProviderAuthentication);
            }
            _ => return Err(SpiceDbError::ProviderUnavailable),
        }
        let media_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(';').next())
            .map(str::trim);
        if media_type != Some("application/json") || response.body().len() > MAX_DOCUMENT_BYTES {
            return Err(SpiceDbError::InvalidResponse);
        }
        let wire: WriteRelationshipsResponse =
            serde_json::from_slice(response.body()).map_err(|_| SpiceDbError::InvalidResponse)?;
        let consistency_token = wire
            .written_at
            .filter(|token| !token.token.is_empty() && token.token.len() <= 4_096)
            .ok_or(SpiceDbError::InvalidResponse)?
            .token;
        Ok(RelationshipWriteReceipt { consistency_token })
    }
}

fn relationship_update(
    intent: &RelationshipOutboxIntent,
) -> Result<RelationshipUpdate<'_>, SpiceDbError> {
    let (resource_type, resource_id) = intent
        .resource
        .split_once(':')
        .ok_or(SpiceDbError::InvalidRequest)?;
    let (subject_type, subject_id) = intent
        .subject
        .split_once(':')
        .ok_or(SpiceDbError::InvalidRequest)?;
    if !is_spicedb_name(resource_type)
        || !is_spicedb_id(resource_id)
        || !is_spicedb_name(subject_type)
        || !is_spicedb_id(subject_id)
        || !is_spicedb_name(&intent.relation)
    {
        return Err(SpiceDbError::InvalidRequest);
    }
    Ok(RelationshipUpdate {
        operation: match intent.operation {
            RelationshipOperation::Grant => "OPERATION_TOUCH",
            RelationshipOperation::Revoke => "OPERATION_DELETE",
        },
        relationship: Relationship {
            resource: ObjectReference {
                object_type: resource_type,
                object_id: resource_id,
            },
            relation: &intent.relation,
            subject: SubjectReference {
                object: ObjectReference {
                    object_type: subject_type,
                    object_id: subject_id,
                },
            },
        },
    })
}

/// Returns an issuer-scoped SpiceDB subject identifier.
#[must_use]
pub fn canonical_subject_id(request: &AccessRequest) -> String {
    let principal = request.context().principal();
    let mut identity =
        Vec::with_capacity(principal.issuer().len() + principal.user_id().as_str().len() + 1);
    identity.extend_from_slice(principal.issuer().as_bytes());
    identity.push(0);
    identity.extend_from_slice(principal.user_id().as_str().as_bytes());
    format!("v1_{}", URL_SAFE_NO_PAD.encode(identity))
}

fn consistency_json(consistency: &ConsistencyRequirement) -> Value {
    match consistency {
        ConsistencyRequirement::MinimizeLatency => json!({"minimizeLatency": true}),
        ConsistencyRequirement::FullyConsistent => json!({"fullyConsistent": true}),
        ConsistencyRequirement::AtLeastAsFresh { token } => {
            json!({"atLeastAsFresh": {"token": token}})
        }
    }
}

fn request_context_json(request: &AccessRequest) -> Option<Value> {
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
    if context.is_empty() {
        None
    } else {
        Some(Value::Object(context))
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
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'_')
}

fn is_spicedb_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 1_024
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'/' | b'_' | b'|' | b'-' | b'=' | b'+')
        })
}

#[derive(Serialize)]
struct WriteRelationshipsRequest<'a> {
    updates: Vec<RelationshipUpdate<'a>>,
}

#[derive(Serialize)]
struct RelationshipUpdate<'a> {
    operation: &'static str,
    relationship: Relationship<'a>,
}

#[derive(Serialize)]
struct Relationship<'a> {
    resource: ObjectReference<'a>,
    relation: &'a str,
    subject: SubjectReference<'a>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct WriteRelationshipsResponse {
    written_at: Option<ZedToken>,
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

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckBulkPermissionsRequest {
    consistency: Value,
    items: Vec<CheckBulkPermissionsRequestItem>,
    with_tracing: bool,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct CheckBulkPermissionsRequestItem {
    resource: OwnedObjectReference,
    permission: String,
    subject: OwnedSubjectReference,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<Value>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct OwnedObjectReference {
    object_type: String,
    object_id: String,
}

#[derive(Serialize)]
struct OwnedSubjectReference {
    object: OwnedObjectReference,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckBulkPermissionsResponse {
    checked_at: Option<ZedToken>,
    pairs: Vec<CheckBulkPermissionsPair>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckBulkPermissionsPair {
    #[serde(default, rename = "request")]
    _request: Option<Value>,
    item: Option<CheckBulkPermissionsResponseItem>,
    error: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct CheckBulkPermissionsResponseItem {
    permissionship: String,
    #[serde(default)]
    partial_caveat_info: Option<Value>,
    #[serde(default, rename = "debugTrace")]
    _debug_trace: Option<Value>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ZedToken {
    token: String,
}

impl From<ContextError> for SpiceDbConfigurationError {
    fn from(_: ContextError) -> Self {
        Self::InvalidPolicyRevision
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::authentication::{RelationshipOperation, RelationshipOutboxIntent};
    use crate::authorization::{ActionName, Resource, ResourceType};
    use crate::testkit::VerifiedAuthContextBuilder;

    #[test]
    fn subject_id_is_issuer_scoped() {
        let first = request("https://issuer-one.test");
        let second = request("https://issuer-two.test");

        assert_ne!(canonical_subject_id(&first), canonical_subject_id(&second));
    }

    #[test]
    fn relationship_writer_maps_grants_and_returns_consistency_token() {
        #[derive(Default)]
        struct FakeTransport {
            request: std::sync::Mutex<Option<Request<Vec<u8>>>>,
        }

        impl SpiceDbTransport for FakeTransport {
            type Error = std::io::Error;

            async fn send(
                &self,
                request: Request<Vec<u8>>,
            ) -> Result<Response<Vec<u8>>, Self::Error> {
                *self.request.lock().expect("request lock") = Some(request);
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(br#"{"writtenAt":{"token":"zed-one"}}"#.to_vec())
                    .expect("response"))
            }
        }

        let writer = SpiceDbRelationshipWriter::new(
            SpiceDbWriteEndpoint::new("https://spicedb.example.test/v1/relationships/write")
                .expect("endpoint"),
            SpiceDbBearerToken::new("provider-secret").expect("token"),
            FakeTransport::default(),
        );
        let intent = RelationshipOutboxIntent {
            operation: RelationshipOperation::Grant,
            resource: "organization:org-one".to_owned(),
            relation: "member".to_owned(),
            subject: "user:user-one".to_owned(),
            resource_revision: 7,
            consistency_token: None,
        };

        let receipt = futures::executor::block_on(writer.write(&[intent])).expect("write");
        assert_eq!(receipt.consistency_token(), "zed-one");
        let request = writer
            .transport
            .request
            .lock()
            .expect("request lock")
            .take()
            .expect("request");
        let body: Value = serde_json::from_slice(request.body()).expect("JSON");
        assert_eq!(body["updates"][0]["operation"], "OPERATION_TOUCH");
        assert_eq!(
            body["updates"][0]["relationship"]["resource"]["objectType"],
            "organization"
        );
        let debug = format!("{writer:?}");
        assert!(!debug.contains("provider-secret"));
        assert!(!debug.contains("spicedb.example.test"));
    }

    #[test]
    fn provider_uses_one_stable_bulk_request_for_bounded_checks() {
        #[derive(Default)]
        struct FakeTransport {
            requests: std::sync::Mutex<Vec<Request<Vec<u8>>>>,
        }

        impl SpiceDbTransport for FakeTransport {
            type Error = std::io::Error;

            async fn send(
                &self,
                request: Request<Vec<u8>>,
            ) -> Result<Response<Vec<u8>>, Self::Error> {
                self.requests.lock().expect("request lock").push(request);
                Ok(Response::builder()
                    .status(StatusCode::OK)
                    .header(CONTENT_TYPE, "application/json")
                    .body(
                        br#"{
                          "checkedAt":{"token":"zed-bulk"},
                          "pairs":[
                            {"item":{"permissionship":"PERMISSIONSHIP_HAS_PERMISSION"}},
                            {"item":{"permissionship":"PERMISSIONSHIP_NO_PERMISSION"}}
                          ]
                        }"#
                        .to_vec(),
                    )
                    .expect("response"))
            }
        }

        let provider = SpiceDbProvider::new(
            SpiceDbEndpoint::new("https://spicedb.example.test/v1/permissions/check")
                .expect("endpoint"),
            SpiceDbBearerToken::new("provider-secret").expect("token"),
            FakeTransport::default(),
            PermissionMap::new([("document.read", "read")]).expect("permission map"),
            "spicedb-v1",
        )
        .expect("provider");
        let requests = [
            request("https://issuer.test"),
            request("https://issuer.test"),
        ];

        let decisions = futures::executor::block_on(
            crate::authorization::Authorizer::new(&provider).batch_check(&requests),
        )
        .expect("bulk decision");

        assert!(decisions[0].is_allowed());
        assert!(!decisions[1].is_allowed());
        let sent = provider.transport.requests.lock().expect("request lock");
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].uri().path(), "/v1/permissions/checkbulk");
    }

    fn request(issuer: &str) -> AccessRequest {
        let context = VerifiedAuthContextBuilder::new()
            .issuer(issuer)
            .build()
            .expect("valid fixture");
        let resource = Resource::new(
            ResourceType::new("document").expect("valid fixture"),
            "document-one",
            context.organization_id().cloned(),
        )
        .expect("valid fixture");
        AccessRequest::new(
            context,
            ActionName::new("document.read").expect("valid fixture"),
            resource,
        )
        .expect("valid fixture")
    }
}
