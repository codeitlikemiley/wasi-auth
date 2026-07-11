//! Bounded OpenID AuthZEN Authorization API 1.0 request and decision types.
//!
//! AuthZEN deliberately permits arbitrary properties and decision context.
//! This crate defines a smaller security profile with explicit subject state,
//! typed attributes, provenance, strict size limits, and fail-closed decision
//! metadata. Credentials and executable obligations are not representable.

#![deny(rustdoc::broken_intra_doc_links)]
#![doc = include_str!("../../../README.md")]

use std::collections::BTreeSet;
use std::fmt;

use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use serde_json::{Map, Value};
use thiserror::Error;

/// AuthZEN profile version implemented by this crate.
pub const AUTHZEN_PROFILE_VERSION: &str = "1.0";
/// Default AuthZEN 1.0 single-evaluation endpoint path.
pub const ACCESS_EVALUATION_PATH: &str = "/access/v1/evaluation";
/// Maximum encoded request or decision body size.
pub const MAX_DOCUMENT_BYTES: usize = 64 * 1024;
/// Maximum number of attributes in one attribute set.
pub const MAX_ATTRIBUTES: usize = 32;
/// Maximum number of values in a string-list attribute.
pub const MAX_ATTRIBUTE_LIST_VALUES: usize = 32;
/// Maximum byte length of one attribute string value.
pub const MAX_ATTRIBUTE_VALUE_LEN: usize = 2 * 1024;
/// Maximum byte length of an entity identifier.
pub const MAX_ENTITY_ID_LEN: usize = 512;
/// Maximum byte length of an entity type.
pub const MAX_ENTITY_TYPE_LEN: usize = 128;
/// Maximum byte length of an action name.
pub const MAX_ACTION_NAME_LEN: usize = 128;
/// Maximum byte length of an attribute name.
pub const MAX_ATTRIBUTE_NAME_LEN: usize = 128;
/// Maximum byte length of a request or decision identifier.
pub const MAX_CORRELATION_ID_LEN: usize = 256;
/// Maximum byte length of a policy, model, or consistency revision.
pub const MAX_REVISION_LEN: usize = 512;
/// Namespaced property used by this bounded AuthZEN profile.
pub const PROFILE_PROPERTY: &str = "wasi_authz";

/// Errors produced while constructing or decoding the bounded contract.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ContractError {
    /// A bounded text value was empty, too long, untrimmed, or contained a control character.
    #[error("invalid {field}; expected non-empty bounded text no longer than {max_len} bytes")]
    InvalidText {
        /// Human-readable field category.
        field: &'static str,
        /// Maximum accepted byte length.
        max_len: usize,
    },
    /// An identifier contained a character outside the stable identifier alphabet.
    #[error("invalid {field}; expected a stable ASCII identifier no longer than {max_len} bytes")]
    InvalidIdentifier {
        /// Human-readable field category.
        field: &'static str,
        /// Maximum accepted byte length.
        max_len: usize,
    },
    /// An attribute name is reserved for credentials or other secret material.
    #[error("attribute name is reserved for secret material")]
    SensitiveAttributeName,
    /// An attribute set exceeded [`MAX_ATTRIBUTES`].
    #[error("too many authorization attributes; maximum is {MAX_ATTRIBUTES}")]
    TooManyAttributes,
    /// An attribute set contained a duplicate name.
    #[error("duplicate authorization attribute: {0}")]
    DuplicateAttribute(String),
    /// A string-list attribute exceeded [`MAX_ATTRIBUTE_LIST_VALUES`].
    #[error("too many string-list values; maximum is {MAX_ATTRIBUTE_LIST_VALUES}")]
    TooManyAttributeValues,
    /// The encoded JSON document exceeded [`MAX_DOCUMENT_BYTES`].
    #[error("authorization document exceeds {MAX_DOCUMENT_BYTES} bytes")]
    DocumentTooLarge,
    /// The JSON document did not conform to the bounded profile.
    #[error("invalid authorization JSON: {0}")]
    InvalidJson(#[from] serde_json::Error),
    /// A decision contained an executable obligation or advice.
    #[error("decision obligations and advice are unsupported")]
    ObligationsUnsupported,
    /// The documented `wasi_authz` decision-context extension was malformed.
    #[error("invalid wasi_authz decision context")]
    InvalidDecisionContext,
}

macro_rules! bounded_text_type {
    ($name:ident, $max:expr, $label:literal, $docs:literal) => {
        #[doc = $docs]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }

        impl $name {
            /// Validates and constructs the value.
            ///
            /// # Errors
            ///
            /// Returns [`ContractError::InvalidText`] for empty, untrimmed,
            /// oversized, or control-character-containing values.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                validate_text(&value, $max, $label)?;
                Ok(Self(value))
            }

            /// Returns the validated string.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

macro_rules! bounded_identifier_type {
    ($name:ident, $max:expr, $label:literal, $docs:literal) => {
        #[doc = $docs]
        #[derive(Clone, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl fmt::Debug for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(concat!(stringify!($name), "([REDACTED])"))
            }
        }

        impl $name {
            /// Validates and constructs the identifier.
            ///
            /// # Errors
            ///
            /// Returns [`ContractError::InvalidIdentifier`] when the value is
            /// empty, oversized, or outside the stable identifier alphabet.
            pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
                let value = value.into();
                validate_identifier(&value, $max, $label)?;
                Ok(Self(value))
            }

            /// Returns the validated identifier.
            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(self.as_str())
            }
        }

        impl<'de> Deserialize<'de> for $name {
            fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
            where
                D: Deserializer<'de>,
            {
                let value = String::deserialize(deserializer)?;
                Self::new(value).map_err(D::Error::custom)
            }
        }
    };
}

bounded_identifier_type!(
    EntityTypeV1,
    MAX_ENTITY_TYPE_LEN,
    "entity type",
    "A stable AuthZEN subject or resource type."
);
bounded_text_type!(
    EntityIdV1,
    MAX_ENTITY_ID_LEN,
    "entity identifier",
    "An immutable AuthZEN subject or resource identifier scoped to its type."
);
bounded_identifier_type!(
    ActionNameV1,
    MAX_ACTION_NAME_LEN,
    "action name",
    "A stable domain action name."
);
/// A stable namespaced authorization attribute name.
///
/// Names associated with credentials or other secret material cannot be
/// constructed. This makes the no-secrets rule apply equally to direct API
/// use and deserialization.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct AttributeNameV1(String);

impl AttributeNameV1 {
    /// Validates and constructs the attribute name.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::SensitiveAttributeName`] for credential-like
    /// names and [`ContractError::InvalidIdentifier`] for malformed names.
    pub fn new(value: impl Into<String>) -> Result<Self, ContractError> {
        let value = value.into();
        validate_identifier(&value, MAX_ATTRIBUTE_NAME_LEN, "attribute name")?;
        if is_sensitive_attribute_name(&value) {
            return Err(ContractError::SensitiveAttributeName);
        }
        Ok(Self(value))
    }

    /// Returns the validated attribute name.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for AttributeNameV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(self.as_str())
    }
}

impl<'de> Deserialize<'de> for AttributeNameV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        Self::new(value).map_err(D::Error::custom)
    }
}
bounded_text_type!(
    IssuerV1,
    MAX_ENTITY_ID_LEN,
    "identity issuer",
    "A trusted identity issuer identifier."
);
bounded_identifier_type!(
    ScopeV1,
    MAX_ATTRIBUTE_NAME_LEN,
    "scope",
    "A validated authorization scope token."
);
bounded_text_type!(
    TenantIdV1,
    MAX_ENTITY_ID_LEN,
    "tenant identifier",
    "An optional trusted tenant identifier."
);
bounded_text_type!(
    RequestIdV1,
    MAX_CORRELATION_ID_LEN,
    "request identifier",
    "A canonical request correlation identifier."
);
bounded_text_type!(
    DecisionIdV1,
    MAX_CORRELATION_ID_LEN,
    "decision identifier",
    "A policy decision correlation identifier."
);
bounded_text_type!(
    PolicyRevisionV1,
    MAX_REVISION_LEN,
    "policy revision",
    "An immutable policy revision or digest."
);
bounded_identifier_type!(
    ModelNameV1,
    MAX_ENTITY_TYPE_LEN,
    "model name",
    "The decision provider model, such as `cedar` or `spicedb`."
);
bounded_text_type!(
    ModelVersionV1,
    MAX_REVISION_LEN,
    "model version",
    "The provider schema or authorization model version."
);
bounded_identifier_type!(
    ReasonCodeV1,
    MAX_ATTRIBUTE_NAME_LEN,
    "reason code",
    "A stable, non-sensitive decision reason code."
);
bounded_text_type!(
    ConsistencyTokenV1,
    MAX_REVISION_LEN,
    "consistency token",
    "An opaque provider consistency token."
);
bounded_text_type!(
    AttributeStringV1,
    MAX_ATTRIBUTE_VALUE_LEN,
    "attribute string",
    "A bounded string authorization attribute value."
);

/// Trusted origin of an authorization attribute.
#[derive(Clone, Copy, Debug, Deserialize, Eq, Hash, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(rename_all = "snake_case")]
pub enum AttributeProvenanceV1 {
    /// Attribute asserted by a validated identity provider.
    IdentityProvider,
    /// Attribute loaded from the authoritative resource store.
    ResourceStore,
    /// Attribute derived by application business logic.
    Application,
    /// Attribute asserted by a trusted ingress or gateway.
    Gateway,
    /// Attribute obtained from a dedicated policy information point.
    PolicyInformationPoint,
}

/// A bounded list of string authorization values.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AttributeStringListV1(Vec<AttributeStringV1>);

impl AttributeStringListV1 {
    /// Validates and constructs a bounded string list.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::TooManyAttributeValues`] when the list has
    /// more than [`MAX_ATTRIBUTE_LIST_VALUES`] entries.
    pub fn new(values: Vec<AttributeStringV1>) -> Result<Self, ContractError> {
        if values.len() > MAX_ATTRIBUTE_LIST_VALUES {
            return Err(ContractError::TooManyAttributeValues);
        }
        Ok(Self(values))
    }

    /// Returns the validated values.
    pub fn as_slice(&self) -> &[AttributeStringV1] {
        &self.0
    }
}

impl<'de> Deserialize<'de> for AttributeStringListV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let values = Vec::<AttributeStringV1>::deserialize(deserializer)?;
        Self::new(values).map_err(D::Error::custom)
    }
}

/// A typed authorization attribute value.
#[derive(Clone, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum AttributeValueV1 {
    /// A bounded string.
    String(AttributeStringV1),
    /// A signed 64-bit integer.
    Integer(i64),
    /// A Boolean value.
    Boolean(bool),
    /// A bounded list of bounded strings.
    StringList(AttributeStringListV1),
}

impl fmt::Debug for AttributeValueV1 {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let kind = match self {
            Self::String(_) => "String",
            Self::Integer(_) => "Integer",
            Self::Boolean(_) => "Boolean",
            Self::StringList(_) => "StringList",
        };
        formatter.debug_tuple(kind).field(&"[REDACTED]").finish()
    }
}

/// One typed, provenance-labeled authorization attribute.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttributeV1 {
    name: AttributeNameV1,
    value: AttributeValueV1,
    provenance: AttributeProvenanceV1,
}

impl<'de> Deserialize<'de> for AttributeV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            name: AttributeNameV1,
            value: AttributeValueV1,
            provenance: AttributeProvenanceV1,
        }

        let wire = Wire::deserialize(deserializer)?;
        Self::new(wire.name, wire.value, wire.provenance).map_err(D::Error::custom)
    }
}

impl AttributeV1 {
    /// Constructs a typed attribute.
    ///
    /// Attribute values must never contain credentials or secrets. The
    /// constructor rejects credential-like names but cannot infer the
    /// sensitivity of arbitrary value content.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::SensitiveAttributeName`] for a reserved name.
    pub fn new(
        name: AttributeNameV1,
        value: AttributeValueV1,
        provenance: AttributeProvenanceV1,
    ) -> Result<Self, ContractError> {
        if is_sensitive_attribute_name(name.as_str()) {
            return Err(ContractError::SensitiveAttributeName);
        }
        Ok(Self {
            name,
            value,
            provenance,
        })
    }

    /// Returns the stable attribute name.
    pub fn name(&self) -> &AttributeNameV1 {
        &self.name
    }

    /// Returns the typed value.
    pub fn value(&self) -> &AttributeValueV1 {
        &self.value
    }

    /// Returns the trusted provenance.
    pub fn provenance(&self) -> AttributeProvenanceV1 {
        self.provenance
    }
}

/// A bounded set of uniquely named attributes.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize)]
#[serde(transparent)]
pub struct AttributesV1(Vec<AttributeV1>);

impl AttributesV1 {
    /// Constructs an empty attribute set.
    pub fn new() -> Self {
        Self::default()
    }

    /// Validates and constructs an attribute set.
    ///
    /// # Errors
    ///
    /// Returns an error for too many attributes, duplicate names, or a
    /// credential-like name.
    pub fn try_from_vec(attributes: Vec<AttributeV1>) -> Result<Self, ContractError> {
        validate_attributes(&attributes)?;
        Ok(Self(attributes))
    }

    /// Inserts one attribute while preserving bounds and uniqueness.
    ///
    /// # Errors
    ///
    /// Returns an error when the set is full or the name is duplicated.
    pub fn insert(&mut self, attribute: AttributeV1) -> Result<(), ContractError> {
        if self.0.len() >= MAX_ATTRIBUTES {
            return Err(ContractError::TooManyAttributes);
        }
        if self.0.iter().any(|item| item.name == attribute.name) {
            return Err(ContractError::DuplicateAttribute(
                attribute.name.to_string(),
            ));
        }
        self.0.push(attribute);
        Ok(())
    }

    /// Returns the attributes in deterministic insertion order.
    pub fn as_slice(&self) -> &[AttributeV1] {
        &self.0
    }

    /// Returns whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl<'de> Deserialize<'de> for AttributesV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let attributes = Vec::<AttributeV1>::deserialize(deserializer)?;
        Self::try_from_vec(attributes).map_err(D::Error::custom)
    }
}

/// An authenticated AuthZEN subject.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticatedSubjectV1 {
    subject_type: EntityTypeV1,
    id: EntityIdV1,
    issuer: IssuerV1,
    tenant_id: Option<TenantIdV1>,
    scopes: Vec<ScopeV1>,
    attributes: AttributesV1,
}

impl AuthenticatedSubjectV1 {
    /// Constructs an authenticated subject with immutable issuer and identifier.
    pub fn new(subject_type: EntityTypeV1, id: EntityIdV1, issuer: IssuerV1) -> Self {
        Self {
            subject_type,
            id,
            issuer,
            tenant_id: None,
            scopes: Vec::new(),
            attributes: AttributesV1::new(),
        }
    }

    /// Sets the optional trusted tenant identifier.
    pub fn with_tenant_id(mut self, tenant_id: TenantIdV1) -> Self {
        self.tenant_id = Some(tenant_id);
        self
    }

    /// Sets validated scope tokens.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::TooManyAttributeValues`] when more than
    /// [`MAX_ATTRIBUTE_LIST_VALUES`] scopes are provided.
    pub fn with_scopes(mut self, scopes: Vec<ScopeV1>) -> Result<Self, ContractError> {
        self.scopes = normalize_scopes(scopes)?;
        Ok(self)
    }

    /// Sets bounded subject attributes.
    pub fn with_attributes(mut self, attributes: AttributesV1) -> Self {
        self.attributes = attributes;
        self
    }

    /// Returns the subject type.
    pub fn subject_type(&self) -> &EntityTypeV1 {
        &self.subject_type
    }

    /// Returns the subject identifier.
    pub fn id(&self) -> &EntityIdV1 {
        &self.id
    }

    /// Returns the trusted issuer.
    pub fn issuer(&self) -> &IssuerV1 {
        &self.issuer
    }

    /// Returns the optional tenant identifier.
    pub fn tenant_id(&self) -> Option<&TenantIdV1> {
        self.tenant_id.as_ref()
    }

    /// Returns the validated scopes.
    pub fn scopes(&self) -> &[ScopeV1] {
        &self.scopes
    }

    /// Returns subject attributes.
    pub fn attributes(&self) -> &AttributesV1 {
        &self.attributes
    }
}

/// Explicit anonymous or authenticated AuthZEN subject state.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum SubjectV1 {
    /// No authenticated principal is present.
    Anonymous,
    /// A principal authenticated by a trusted issuer.
    Authenticated(AuthenticatedSubjectV1),
}

impl SubjectV1 {
    /// Returns whether the subject is authenticated.
    pub fn is_authenticated(&self) -> bool {
        matches!(self, Self::Authenticated(_))
    }

    /// Returns the authenticated subject, if present.
    pub fn authenticated(&self) -> Option<&AuthenticatedSubjectV1> {
        match self {
            Self::Anonymous => None,
            Self::Authenticated(subject) => Some(subject),
        }
    }
}

#[derive(Serialize)]
struct SubjectWireRef<'a> {
    #[serde(rename = "type")]
    subject_type: &'a str,
    id: &'a str,
    properties: SubjectPropertiesWireRef<'a>,
}

#[derive(Serialize)]
struct SubjectPropertiesWireRef<'a> {
    #[serde(rename = "wasi_authz")]
    profile: SubjectProfileWireRef<'a>,
}

#[derive(Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum SubjectProfileWireRef<'a> {
    Anonymous,
    Authenticated {
        issuer: &'a IssuerV1,
        #[serde(skip_serializing_if = "Option::is_none")]
        tenant_id: Option<&'a TenantIdV1>,
        #[serde(skip_serializing_if = "<[ScopeV1]>::is_empty")]
        scopes: &'a [ScopeV1],
        #[serde(skip_serializing_if = "AttributesV1::is_empty")]
        attributes: &'a AttributesV1,
    },
}

#[derive(Deserialize)]
struct SubjectWireOwned {
    #[serde(rename = "type")]
    subject_type: String,
    id: String,
    properties: SubjectPropertiesWireOwned,
}

#[derive(Deserialize)]
struct SubjectPropertiesWireOwned {
    #[serde(rename = "wasi_authz")]
    profile: SubjectProfileWireOwned,
}

#[derive(Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
enum SubjectProfileWireOwned {
    Anonymous,
    Authenticated {
        issuer: IssuerV1,
        #[serde(default)]
        tenant_id: Option<TenantIdV1>,
        #[serde(default)]
        scopes: Vec<ScopeV1>,
        #[serde(default)]
        attributes: AttributesV1,
    },
}

impl Serialize for SubjectV1 {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match self {
            Self::Anonymous => SubjectWireRef {
                subject_type: "anonymous",
                id: "anonymous",
                properties: SubjectPropertiesWireRef {
                    profile: SubjectProfileWireRef::Anonymous,
                },
            }
            .serialize(serializer),
            Self::Authenticated(subject) => SubjectWireRef {
                subject_type: subject.subject_type.as_str(),
                id: subject.id.as_str(),
                properties: SubjectPropertiesWireRef {
                    profile: SubjectProfileWireRef::Authenticated {
                        issuer: &subject.issuer,
                        tenant_id: subject.tenant_id.as_ref(),
                        scopes: &subject.scopes,
                        attributes: &subject.attributes,
                    },
                },
            }
            .serialize(serializer),
        }
    }
}

impl<'de> Deserialize<'de> for SubjectV1 {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let wire = SubjectWireOwned::deserialize(deserializer)?;
        match wire.properties.profile {
            SubjectProfileWireOwned::Anonymous => {
                if wire.subject_type != "anonymous" || wire.id != "anonymous" {
                    return Err(D::Error::custom(
                        "anonymous subject must use type and id `anonymous`",
                    ));
                }
                Ok(Self::Anonymous)
            }
            SubjectProfileWireOwned::Authenticated {
                issuer,
                tenant_id,
                scopes,
                attributes,
            } => {
                let scopes = normalize_scopes(scopes).map_err(D::Error::custom)?;
                let subject_type =
                    EntityTypeV1::new(wire.subject_type).map_err(D::Error::custom)?;
                if subject_type.as_str() == "anonymous" {
                    return Err(D::Error::custom(
                        "authenticated subject cannot use anonymous type",
                    ));
                }
                let id = EntityIdV1::new(wire.id).map_err(D::Error::custom)?;
                Ok(Self::Authenticated(AuthenticatedSubjectV1 {
                    subject_type,
                    id,
                    issuer,
                    tenant_id,
                    scopes,
                    attributes,
                }))
            }
        }
    }
}

/// AuthZEN resource properties for the bounded profile.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
struct EntityPropertiesV1 {
    #[serde(rename = "wasi_authz")]
    profile: EntityAttributeProfileV1,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct EntityAttributeProfileV1 {
    #[serde(default, skip_serializing_if = "AttributesV1::is_empty")]
    attributes: AttributesV1,
}

/// A typed AuthZEN resource.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResourceV1 {
    #[serde(rename = "type")]
    resource_type: EntityTypeV1,
    id: EntityIdV1,
    properties: EntityPropertiesV1,
}

impl ResourceV1 {
    /// Validates and constructs a resource without attributes.
    ///
    /// # Errors
    ///
    /// Returns a contract error when the resource type or identifier is invalid.
    pub fn new(
        resource_type: impl Into<String>,
        id: impl Into<String>,
    ) -> Result<Self, ContractError> {
        Ok(Self::from_parts(
            EntityTypeV1::new(resource_type)?,
            EntityIdV1::new(id)?,
        ))
    }

    /// Constructs a resource from separately validated parts.
    pub fn from_parts(resource_type: EntityTypeV1, id: EntityIdV1) -> Self {
        Self {
            resource_type,
            id,
            properties: EntityPropertiesV1::default(),
        }
    }

    /// Sets bounded resource attributes.
    pub fn with_attributes(mut self, attributes: AttributesV1) -> Self {
        self.properties.profile.attributes = attributes;
        self
    }

    /// Returns the resource type.
    pub fn resource_type(&self) -> &EntityTypeV1 {
        &self.resource_type
    }

    /// Returns the resource identifier.
    pub fn id(&self) -> &EntityIdV1 {
        &self.id
    }

    /// Returns resource attributes.
    pub fn attributes(&self) -> &AttributesV1 {
        &self.properties.profile.attributes
    }
}

/// A stable AuthZEN action.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ActionV1 {
    name: ActionNameV1,
    properties: EntityPropertiesV1,
}

impl ActionV1 {
    /// Validates and constructs an action without attributes.
    ///
    /// # Errors
    ///
    /// Returns a contract error when the action name is invalid.
    pub fn new(name: impl Into<String>) -> Result<Self, ContractError> {
        Ok(Self::from_name(ActionNameV1::new(name)?))
    }

    /// Constructs an action from a separately validated name.
    pub fn from_name(name: ActionNameV1) -> Self {
        Self {
            name,
            properties: EntityPropertiesV1::default(),
        }
    }

    /// Sets bounded action attributes.
    pub fn with_attributes(mut self, attributes: AttributesV1) -> Self {
        self.properties.profile.attributes = attributes;
        self
    }

    /// Returns the action name.
    pub fn name(&self) -> &ActionNameV1 {
        &self.name
    }

    /// Returns action attributes.
    pub fn attributes(&self) -> &AttributesV1 {
        &self.properties.profile.attributes
    }
}

/// Consistency requested from a stateful authorization provider.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum ConsistencyRequirementV1 {
    /// Prefer provider caches and minimum latency.
    MinimizeLatency,
    /// Require a snapshot at least as fresh as the supplied token.
    AtLeastAsFresh {
        /// Opaque provider consistency token.
        token: ConsistencyTokenV1,
    },
    /// Require the provider's latest available state.
    FullyConsistent,
}

/// Ergonomic name for an AuthZEN access evaluation request.
pub type AccessEvaluation = AccessRequestV1;
/// Ergonomic name for a stable AuthZEN action.
pub type Action = ActionV1;
/// Ergonomic name for a typed AuthZEN resource.
pub type Resource = ResourceV1;
/// Ergonomic name for a provider consistency requirement.
pub type Consistency = ConsistencyRequirementV1;

/// Bounded AuthZEN environmental context.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
pub struct ContextV1 {
    #[serde(rename = "wasi_authz")]
    profile: RequestContextProfileV1,
}

#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct RequestContextProfileV1 {
    #[serde(default, skip_serializing_if = "AttributesV1::is_empty")]
    attributes: AttributesV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consistency: Option<ConsistencyRequirementV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    request_id: Option<RequestIdV1>,
}

impl ContextV1 {
    /// Constructs empty bounded context.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets trusted contextual attributes.
    pub fn with_attributes(mut self, attributes: AttributesV1) -> Self {
        self.profile.attributes = attributes;
        self
    }

    /// Sets a provider consistency requirement.
    pub fn with_consistency(mut self, consistency: ConsistencyRequirementV1) -> Self {
        self.profile.consistency = Some(consistency);
        self
    }

    /// Sets a canonical request identifier used only for correlation.
    pub fn with_request_id(mut self, request_id: RequestIdV1) -> Self {
        self.profile.request_id = Some(request_id);
        self
    }

    /// Returns contextual attributes.
    pub fn attributes(&self) -> &AttributesV1 {
        &self.profile.attributes
    }

    /// Returns the requested provider consistency.
    pub fn consistency(&self) -> Option<&ConsistencyRequirementV1> {
        self.profile.consistency.as_ref()
    }

    /// Returns the correlation request identifier.
    pub fn request_id(&self) -> Option<&RequestIdV1> {
        self.profile.request_id.as_ref()
    }
}

/// A bounded AuthZEN 1.0 access evaluation request.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct AccessRequestV1 {
    subject: SubjectV1,
    action: ActionV1,
    resource: ResourceV1,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    context: Option<ContextV1>,
}

impl AccessRequestV1 {
    /// Constructs an access evaluation request without environmental context.
    pub fn new(subject: SubjectV1, action: ActionV1, resource: ResourceV1) -> Self {
        Self {
            subject,
            action,
            resource,
            context: None,
        }
    }

    /// Sets bounded environmental context.
    pub fn with_context(mut self, context: ContextV1) -> Self {
        self.context = Some(context);
        self
    }

    /// Returns the subject.
    pub fn subject(&self) -> &SubjectV1 {
        &self.subject
    }

    /// Returns the domain action.
    pub fn action(&self) -> &ActionV1 {
        &self.action
    }

    /// Returns the typed resource.
    pub fn resource(&self) -> &ResourceV1 {
        &self.resource
    }

    /// Returns environmental context.
    pub fn context(&self) -> Option<&ContextV1> {
        self.context.as_ref()
    }

    /// Encodes this request as bounded AuthZEN JSON.
    ///
    /// # Errors
    ///
    /// Returns [`ContractError::DocumentTooLarge`] when the encoded document
    /// exceeds [`MAX_DOCUMENT_BYTES`], or a JSON serialization error.
    pub fn to_json_vec(&self) -> Result<Vec<u8>, ContractError> {
        encode_bounded(self)
    }

    /// Decodes and validates bounded AuthZEN JSON.
    ///
    /// # Errors
    ///
    /// Returns a contract error for oversized, malformed, or out-of-profile input.
    pub fn from_json_slice(input: &[u8]) -> Result<Self, ContractError> {
        decode_bounded(input)
    }
}

/// Optional namespaced metadata carried in an AuthZEN decision context.
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DecisionMetadataV1 {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    decision_id: Option<DecisionIdV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    policy_revision: Option<PolicyRevisionV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model: Option<ModelNameV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model_version: Option<ModelVersionV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    reason_code: Option<ReasonCodeV1>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    consistency_token: Option<ConsistencyTokenV1>,
}

impl DecisionMetadataV1 {
    /// Constructs empty decision metadata.
    pub fn new() -> Self {
        Self::default()
    }

    /// Sets the decision correlation identifier.
    pub fn with_decision_id(mut self, decision_id: DecisionIdV1) -> Self {
        self.decision_id = Some(decision_id);
        self
    }

    /// Sets the immutable policy revision.
    pub fn with_policy_revision(mut self, revision: PolicyRevisionV1) -> Self {
        self.policy_revision = Some(revision);
        self
    }

    /// Sets provider model metadata.
    pub fn with_model(mut self, model: ModelNameV1, version: ModelVersionV1) -> Self {
        self.model = Some(model);
        self.model_version = Some(version);
        self
    }

    /// Sets a stable, non-sensitive reason code.
    pub fn with_reason_code(mut self, reason_code: ReasonCodeV1) -> Self {
        self.reason_code = Some(reason_code);
        self
    }

    /// Sets an opaque provider consistency token.
    pub fn with_consistency_token(mut self, token: ConsistencyTokenV1) -> Self {
        self.consistency_token = Some(token);
        self
    }

    /// Returns the decision identifier.
    pub fn decision_id(&self) -> Option<&DecisionIdV1> {
        self.decision_id.as_ref()
    }

    /// Returns the policy revision.
    pub fn policy_revision(&self) -> Option<&PolicyRevisionV1> {
        self.policy_revision.as_ref()
    }

    /// Returns the provider model name.
    pub fn model(&self) -> Option<&ModelNameV1> {
        self.model.as_ref()
    }

    /// Returns the provider model version.
    pub fn model_version(&self) -> Option<&ModelVersionV1> {
        self.model_version.as_ref()
    }

    /// Returns the safe reason code.
    pub fn reason_code(&self) -> Option<&ReasonCodeV1> {
        self.reason_code.as_ref()
    }

    /// Returns the provider consistency token.
    pub fn consistency_token(&self) -> Option<&ConsistencyTokenV1> {
        self.consistency_token.as_ref()
    }

    fn is_empty(&self) -> bool {
        self == &Self::default()
    }
}

/// A successful AuthZEN evaluation response.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionResponseV1 {
    decision: bool,
    metadata: DecisionMetadataV1,
}

impl DecisionResponseV1 {
    /// Constructs an explicit allow decision.
    pub fn allow(metadata: DecisionMetadataV1) -> Self {
        Self {
            decision: true,
            metadata,
        }
    }

    /// Constructs an explicit deny decision.
    pub fn deny(metadata: DecisionMetadataV1) -> Self {
        Self {
            decision: false,
            metadata,
        }
    }

    /// Returns whether the operation is explicitly permitted.
    pub fn is_allowed(&self) -> bool {
        self.decision
    }

    /// Returns whether the operation is explicitly denied.
    pub fn is_denied(&self) -> bool {
        !self.decision
    }

    /// Returns bounded decision metadata.
    pub fn metadata(&self) -> &DecisionMetadataV1 {
        &self.metadata
    }

    /// Encodes this decision as bounded AuthZEN JSON.
    ///
    /// # Errors
    ///
    /// Returns a contract error when serialization fails or the document is oversized.
    pub fn to_json_vec(&self) -> Result<Vec<u8>, ContractError> {
        encode_bounded(&DecisionWireRef {
            decision: self.decision,
            context: (!self.metadata.is_empty()).then_some(DecisionContextWireRef {
                profile: &self.metadata,
            }),
        })
    }

    /// Decodes a successful AuthZEN response and rejects unsupported obligations.
    ///
    /// # Errors
    ///
    /// Returns a contract error for malformed JSON, a malformed documented
    /// extension, or a non-empty obligation that this PEP cannot fulfill.
    /// Unknown standard AuthZEN response members are ignored as required by
    /// AuthZEN 1.0 section 10.1.1.
    pub fn from_json_slice(input: &[u8]) -> Result<Self, ContractError> {
        if input.len() > MAX_DOCUMENT_BYTES {
            return Err(ContractError::DocumentTooLarge);
        }
        let raw = serde_json::from_slice::<RawDecisionWire>(input)?;
        let metadata = parse_decision_context(raw.context)?;
        Ok(Self {
            decision: raw.decision,
            metadata,
        })
    }
}

#[derive(Serialize)]
struct DecisionWireRef<'a> {
    decision: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    context: Option<DecisionContextWireRef<'a>>,
}

#[derive(Serialize)]
struct DecisionContextWireRef<'a> {
    #[serde(rename = "wasi_authz")]
    profile: &'a DecisionMetadataV1,
}

#[derive(Deserialize)]
struct RawDecisionWire {
    decision: bool,
    #[serde(default)]
    context: Option<Map<String, Value>>,
}

fn parse_decision_context(
    context: Option<Map<String, Value>>,
) -> Result<DecisionMetadataV1, ContractError> {
    let Some(mut context) = context else {
        return Ok(DecisionMetadataV1::new());
    };
    if context.is_empty() {
        return Ok(DecisionMetadataV1::new());
    }
    for reserved in ["obligations", "obligation"] {
        if context.get(reserved).is_some_and(is_nonempty_json_value) {
            return Err(ContractError::ObligationsUnsupported);
        }
    }
    let Some(profile) = context.remove(PROFILE_PROPERTY) else {
        return Ok(DecisionMetadataV1::new());
    };
    let Some(profile_object) = profile.as_object() else {
        return Err(ContractError::InvalidDecisionContext);
    };
    for reserved in ["obligations", "obligation"] {
        if profile_object
            .get(reserved)
            .is_some_and(is_nonempty_json_value)
        {
            return Err(ContractError::ObligationsUnsupported);
        }
    }
    serde_json::from_value(profile).map_err(ContractError::InvalidJson)
}

fn is_nonempty_json_value(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Array(value) => !value.is_empty(),
        Value::Object(value) => !value.is_empty(),
        Value::Bool(_) | Value::Number(_) | Value::String(_) => true,
    }
}

fn encode_bounded(value: &impl Serialize) -> Result<Vec<u8>, ContractError> {
    let encoded = serde_json::to_vec(value)?;
    if encoded.len() > MAX_DOCUMENT_BYTES {
        return Err(ContractError::DocumentTooLarge);
    }
    Ok(encoded)
}

fn decode_bounded<T>(input: &[u8]) -> Result<T, ContractError>
where
    T: for<'de> Deserialize<'de>,
{
    if input.len() > MAX_DOCUMENT_BYTES {
        return Err(ContractError::DocumentTooLarge);
    }
    serde_json::from_slice(input).map_err(ContractError::InvalidJson)
}

fn validate_text(value: &str, max_len: usize, field: &'static str) -> Result<(), ContractError> {
    let valid = !value.is_empty()
        && value.len() <= max_len
        && value.trim() == value
        && !value.chars().any(char::is_control);
    if valid {
        Ok(())
    } else {
        Err(ContractError::InvalidText { field, max_len })
    }
}

fn validate_identifier(
    value: &str,
    max_len: usize,
    field: &'static str,
) -> Result<(), ContractError> {
    let valid = !value.is_empty()
        && value.len() <= max_len
        && value.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'/')
        });
    if valid {
        Ok(())
    } else {
        Err(ContractError::InvalidIdentifier { field, max_len })
    }
}

fn validate_attributes(attributes: &[AttributeV1]) -> Result<(), ContractError> {
    if attributes.len() > MAX_ATTRIBUTES {
        return Err(ContractError::TooManyAttributes);
    }
    let mut names = BTreeSet::new();
    for attribute in attributes {
        if is_sensitive_attribute_name(attribute.name.as_str()) {
            return Err(ContractError::SensitiveAttributeName);
        }
        if !names.insert(attribute.name.as_str()) {
            return Err(ContractError::DuplicateAttribute(
                attribute.name.to_string(),
            ));
        }
    }
    Ok(())
}

fn normalize_scopes(mut scopes: Vec<ScopeV1>) -> Result<Vec<ScopeV1>, ContractError> {
    if scopes.len() > MAX_ATTRIBUTE_LIST_VALUES {
        return Err(ContractError::TooManyAttributeValues);
    }
    scopes.sort_unstable();
    scopes.dedup();
    Ok(scopes)
}

fn is_sensitive_attribute_name(name: &str) -> bool {
    name.split(['.', '-', '_', ':', '/']).any(|segment| {
        matches!(
            segment.to_ascii_lowercase().as_str(),
            "authorization"
                | "cookie"
                | "credential"
                | "password"
                | "secret"
                | "token"
                | "access-token"
                | "refresh-token"
                | "client-secret"
                | "session-secret"
        )
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn authenticated_request() -> AccessRequestV1 {
        let subject = AuthenticatedSubjectV1::new(
            EntityTypeV1::new("user").expect("valid fixture"),
            EntityIdV1::new("alice").expect("valid fixture"),
            IssuerV1::new("https://identity.example").expect("valid fixture"),
        );
        AccessRequestV1::new(
            SubjectV1::Authenticated(subject),
            ActionV1::new("document.read").expect("valid fixture"),
            ResourceV1::from_parts(
                EntityTypeV1::new("document").expect("valid fixture"),
                EntityIdV1::new("report-1").expect("valid fixture"),
            ),
        )
    }

    #[test]
    fn authenticated_request_round_trips_through_authzen_json() {
        let request = authenticated_request();
        let encoded = request.to_json_vec().expect("fixture should encode");
        let decoded = AccessRequestV1::from_json_slice(&encoded).expect("fixture should decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn unknown_standard_request_members_are_ignored() {
        let request = authenticated_request().with_context(ContextV1::new());
        let mut value = serde_json::to_value(&request).expect("fixture should encode");
        let object = value.as_object_mut().expect("request is an object");
        object.insert("vendor_extension".to_owned(), Value::Bool(true));
        object["subject"]
            .as_object_mut()
            .expect("subject is an object")
            .insert("vendor_subject".to_owned(), Value::String("ignored".into()));
        object["subject"]["properties"]
            .as_object_mut()
            .expect("properties is an object")
            .insert("department".to_owned(), Value::String("Sales".into()));
        object["resource"]
            .as_object_mut()
            .expect("resource is an object")
            .insert("vendor_resource".to_owned(), Value::Bool(true));
        object["action"]
            .as_object_mut()
            .expect("action is an object")
            .insert("vendor_action".to_owned(), Value::Bool(true));
        object["context"]
            .as_object_mut()
            .expect("context is an object")
            .insert(
                "time".to_owned(),
                Value::String("2026-07-10T00:00:00Z".into()),
            );

        let encoded = serde_json::to_vec(&value).expect("fixture should encode");
        let decoded = AccessRequestV1::from_json_slice(&encoded)
            .expect("AuthZEN requires unknown members to be ignored");

        assert_eq!(decoded, request);
    }

    #[test]
    fn anonymous_subject_has_explicit_wire_state() {
        let request = AccessRequestV1::new(
            SubjectV1::Anonymous,
            ActionV1::new("page.view").expect("valid fixture"),
            ResourceV1::new("http-route", "home").expect("valid fixture"),
        );
        let encoded = request.to_json_vec().expect("fixture should encode");
        let value: Value = serde_json::from_slice(&encoded).expect("fixture should be JSON");

        assert_eq!(
            value["subject"]["properties"]["wasi_authz"]["state"],
            "anonymous"
        );
    }

    #[test]
    fn sensitive_attribute_name_is_rejected() {
        let result = AttributeNameV1::new("oauth.access_token");

        assert!(matches!(result, Err(ContractError::SensitiveAttributeName)));
    }

    #[test]
    fn sensitive_attribute_name_is_rejected_during_deserialization() {
        let input = br#"{"name":"oauth.access_token","value":{"type":"boolean","value":true},"provenance":"application"}"#;

        let result = serde_json::from_slice::<AttributeV1>(input);

        assert!(result.is_err());
    }

    #[test]
    fn duplicate_attribute_names_are_rejected() {
        let attribute = AttributeV1::new(
            AttributeNameV1::new("document.owner").expect("valid fixture"),
            AttributeValueV1::Boolean(true),
            AttributeProvenanceV1::ResourceStore,
        )
        .expect("valid fixture");

        let result = AttributesV1::try_from_vec(vec![attribute.clone(), attribute]);

        assert!(matches!(result, Err(ContractError::DuplicateAttribute(_))));
    }

    #[test]
    fn oversized_document_is_rejected_before_json_parsing() {
        let oversized = vec![b' '; MAX_DOCUMENT_BYTES + 1];

        let result = AccessRequestV1::from_json_slice(&oversized);

        assert!(matches!(result, Err(ContractError::DocumentTooLarge)));
    }

    #[test]
    fn nonempty_decision_obligation_is_rejected_fail_closed() {
        let input = br#"{"decision":true,"context":{"obligations":[{"name":"audit"}]}}"#;

        let result = DecisionResponseV1::from_json_slice(input);

        assert!(matches!(result, Err(ContractError::ObligationsUnsupported)));
    }

    #[test]
    fn malformed_scalar_obligation_is_rejected_fail_closed() {
        let input = br#"{"decision":true,"context":{"obligations":false}}"#;

        let result = DecisionResponseV1::from_json_slice(input);

        assert!(matches!(result, Err(ContractError::ObligationsUnsupported)));
    }

    #[test]
    fn empty_obligations_and_unknown_context_are_ignored() {
        let input = br#"{"decision":true,"vendor":true,"context":{"obligations":[],"reason":"allowed","advice":{"message":"ignored"},"cache":{"max_age":30}}}"#;

        let decision = DecisionResponseV1::from_json_slice(input)
            .expect("unknown members and empty obligations are safe to ignore");

        assert!(decision.is_allowed());
        assert_eq!(decision.metadata(), &DecisionMetadataV1::new());
    }

    #[test]
    fn unknown_member_inside_documented_extension_is_rejected() {
        let input = br#"{"decision":true,"context":{"wasi_authz":{"cache":{"max_age":30}}}}"#;

        let result = DecisionResponseV1::from_json_slice(input);

        assert!(matches!(result, Err(ContractError::InvalidJson(_))));
    }

    #[test]
    fn decision_metadata_round_trips() {
        let metadata = DecisionMetadataV1::new()
            .with_decision_id(DecisionIdV1::new("decision-1").expect("valid fixture"))
            .with_policy_revision(PolicyRevisionV1::new("sha256:abc123").expect("valid fixture"))
            .with_model(
                ModelNameV1::new("cedar").expect("valid fixture"),
                ModelVersionV1::new("schema-1").expect("valid fixture"),
            );
        let response = DecisionResponseV1::allow(metadata);
        let encoded = response.to_json_vec().expect("fixture should encode");
        let decoded = DecisionResponseV1::from_json_slice(&encoded).expect("fixture should decode");

        assert_eq!(decoded, response);
    }

    #[test]
    fn consistency_requirement_round_trips() {
        let context = ContextV1::new().with_consistency(ConsistencyRequirementV1::AtLeastAsFresh {
            token: ConsistencyTokenV1::new("opaque-zed-token").expect("valid fixture"),
        });
        let request = authenticated_request().with_context(context);
        let encoded = request.to_json_vec().expect("fixture should encode");
        let decoded = AccessRequestV1::from_json_slice(&encoded).expect("fixture should decode");

        assert_eq!(decoded, request);
    }

    #[test]
    fn scopes_are_sorted_and_deduplicated() {
        let subject = AuthenticatedSubjectV1::new(
            EntityTypeV1::new("user").expect("valid fixture"),
            EntityIdV1::new("alice").expect("valid fixture"),
            IssuerV1::new("https://identity.example").expect("valid fixture"),
        )
        .with_scopes(vec![
            ScopeV1::new("orders.write").expect("valid fixture"),
            ScopeV1::new("orders.read").expect("valid fixture"),
            ScopeV1::new("orders.write").expect("valid fixture"),
        ])
        .expect("valid fixture");

        assert_eq!(
            subject
                .scopes()
                .iter()
                .map(ScopeV1::as_str)
                .collect::<Vec<_>>(),
            vec!["orders.read", "orders.write"]
        );
    }

    #[test]
    fn debug_output_redacts_identity_attributes_and_decision_metadata() {
        let subject = AuthenticatedSubjectV1::new(
            EntityTypeV1::new("principal").expect("valid fixture"),
            EntityIdV1::new("subject-debug-sentinel").expect("valid fixture"),
            IssuerV1::new("issuer-debug-sentinel.example").expect("valid fixture"),
        )
        .with_scopes(vec![
            ScopeV1::new("scope-debug-sentinel").expect("valid fixture"),
        ])
        .expect("valid fixture")
        .with_attributes(
            AttributesV1::try_from_vec(vec![
                AttributeV1::new(
                    AttributeNameV1::new("department").expect("valid fixture"),
                    AttributeValueV1::String(
                        AttributeStringV1::new("attribute-debug-sentinel").expect("valid fixture"),
                    ),
                    AttributeProvenanceV1::IdentityProvider,
                )
                .expect("valid fixture"),
            ])
            .expect("valid fixture"),
        );
        let evaluation = AccessEvaluation::new(
            SubjectV1::Authenticated(subject),
            Action::new("document.read").expect("valid fixture"),
            Resource::new("document", "resource-debug-sentinel").expect("valid fixture"),
        )
        .with_context(ContextV1::new().with_consistency(
            ConsistencyRequirementV1::AtLeastAsFresh {
                token:
                    ConsistencyTokenV1::new("consistency-debug-sentinel").expect("valid fixture"),
            },
        ));
        let decision = DecisionResponseV1::allow(
            DecisionMetadataV1::new()
                .with_decision_id(
                    DecisionIdV1::new("decision-debug-sentinel").expect("valid fixture"),
                )
                .with_policy_revision(
                    PolicyRevisionV1::new("policy-debug-sentinel").expect("valid fixture"),
                ),
        );

        for debug in [format!("{evaluation:?}"), format!("{decision:?}")] {
            assert!(debug.contains("[REDACTED]"));
            assert!(!debug.contains("debug-sentinel"));
        }
    }
}
