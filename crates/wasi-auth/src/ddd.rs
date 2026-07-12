//! Optional DDD/CQRS event-sourcing adapters.
//!
//! Secret bytes never appear in these events. Credential events contain only
//! references and versions committed with the separate secret store.

use std::collections::BTreeSet;

use ddd_cqrs_es::{Aggregate, DomainEvent};
use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::authentication::AuthenticationError;
use crate::context::{CredentialId, OrganizationId, UserId};

/// DDD command rejection for authentication aggregates.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum DddAuthError {
    /// Aggregate was already initialized.
    #[error("authentication aggregate already exists")]
    AlreadyExists,
    /// Aggregate was not initialized.
    #[error("authentication aggregate does not exist")]
    NotFound,
    /// Domain invariant rejected the operation.
    #[error("authentication invariant rejected the command")]
    Invariant,
}

impl From<AuthenticationError> for DddAuthError {
    fn from(_: AuthenticationError) -> Self {
        Self::Invariant
    }
}

/// User aggregate command. Password hashes and tokens are intentionally absent.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum UserCommand {
    /// Registers a pending user.
    Register {
        /// Global user identifier.
        user_id: UserId,
        /// Normalized primary email.
        primary_email: String,
    },
    /// Marks the primary email verified.
    VerifyEmail,
    /// Links a separately stored credential reference.
    LinkCredential {
        /// Credential identifier.
        credential_id: CredentialId,
        /// Monotonic secret version.
        secret_version: u64,
    },
    /// Disables the user and triggers session revocation through the outbox.
    Disable,
    /// Re-enables the user after administrative recovery.
    Enable,
}

/// Sanitized user domain event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum UserEvent {
    /// User registration was accepted.
    Registered {
        /// Global user identifier.
        user_id: UserId,
        /// Normalized primary email.
        primary_email: String,
    },
    /// Primary email was verified.
    EmailVerified,
    /// A secret-store credential reference was linked.
    CredentialLinked {
        /// Credential identifier.
        credential_id: CredentialId,
        /// Monotonic secret version.
        secret_version: u64,
    },
    /// User was disabled.
    Disabled,
    /// User was re-enabled.
    Enabled,
}

impl DomainEvent for UserEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Registered { .. } => "auth.user.registered",
            Self::EmailVerified => "auth.user.email-verified",
            Self::CredentialLinked { .. } => "auth.user.credential-linked",
            Self::Disabled => "auth.user.disabled",
            Self::Enabled => "auth.user.enabled",
        }
    }
}

/// Event-sourced user state containing no secret material.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct UserAggregate {
    user_id: Option<UserId>,
    primary_email: Option<String>,
    email_verified: bool,
    disabled: bool,
    credential_versions: Vec<(CredentialId, u64)>,
    revision: u64,
}

impl Aggregate for UserAggregate {
    type Id = UserId;
    type Command = UserCommand;
    type Event = UserEvent;
    type Error = DddAuthError;

    fn aggregate_type() -> &'static str {
        "auth_user"
    }

    fn revision(&self) -> u64 {
        self.revision
    }

    fn apply(&mut self, event: &Self::Event) {
        match event {
            UserEvent::Registered {
                user_id,
                primary_email,
            } => {
                self.user_id = Some(user_id.clone());
                self.primary_email = Some(primary_email.clone());
            }
            UserEvent::EmailVerified => self.email_verified = true,
            UserEvent::CredentialLinked {
                credential_id,
                secret_version,
            } => self
                .credential_versions
                .push((credential_id.clone(), *secret_version)),
            UserEvent::Disabled => self.disabled = true,
            UserEvent::Enabled => self.disabled = false,
        }
        self.revision += 1;
    }

    fn handle(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        match command {
            UserCommand::Register {
                user_id,
                primary_email,
            } => {
                if self.user_id.is_some() {
                    return Err(DddAuthError::AlreadyExists);
                }
                if primary_email.trim() != primary_email || !primary_email.contains('@') {
                    return Err(DddAuthError::Invariant);
                }
                Ok(vec![UserEvent::Registered {
                    user_id,
                    primary_email,
                }])
            }
            UserCommand::VerifyEmail => {
                self.ensure_exists()?;
                if self.email_verified {
                    Ok(Vec::new())
                } else {
                    Ok(vec![UserEvent::EmailVerified])
                }
            }
            UserCommand::LinkCredential {
                credential_id,
                secret_version,
            } => {
                self.ensure_active()?;
                if secret_version == 0 {
                    return Err(DddAuthError::Invariant);
                }
                Ok(vec![UserEvent::CredentialLinked {
                    credential_id,
                    secret_version,
                }])
            }
            UserCommand::Disable => {
                self.ensure_exists()?;
                if self.disabled {
                    Ok(Vec::new())
                } else {
                    Ok(vec![UserEvent::Disabled])
                }
            }
            UserCommand::Enable => {
                self.ensure_exists()?;
                if self.disabled {
                    Ok(vec![UserEvent::Enabled])
                } else {
                    Ok(Vec::new())
                }
            }
        }
    }

    fn new() -> Self {
        Self::default()
    }
}

impl UserAggregate {
    fn ensure_exists(&self) -> Result<(), DddAuthError> {
        if self.user_id.is_some() {
            Ok(())
        } else {
            Err(DddAuthError::NotFound)
        }
    }

    fn ensure_active(&self) -> Result<(), DddAuthError> {
        self.ensure_exists()?;
        if self.disabled {
            Err(DddAuthError::Invariant)
        } else {
            Ok(())
        }
    }
}

/// Organization aggregate command preserving a non-empty owner set.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum OrganizationCommand {
    /// Creates an organization with its first owner.
    Create {
        /// Organization identifier.
        organization_id: OrganizationId,
        /// First owner.
        owner_id: UserId,
        /// Display name.
        name: String,
    },
    /// Adds another owner.
    AddOwner {
        /// New owner identifier.
        user_id: UserId,
    },
    /// Removes an owner if at least one remains.
    RemoveOwner {
        /// Owner identifier.
        user_id: UserId,
    },
    /// Archives the organization.
    Archive,
}

/// Organization domain event.
#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[non_exhaustive]
pub enum OrganizationEvent {
    /// Organization was created.
    Created {
        /// Organization identifier.
        organization_id: OrganizationId,
        /// First owner.
        owner_id: UserId,
        /// Display name.
        name: String,
    },
    /// Owner was added.
    OwnerAdded {
        /// Owner identifier.
        user_id: UserId,
    },
    /// Owner was removed.
    OwnerRemoved {
        /// Owner identifier.
        user_id: UserId,
    },
    /// Organization was archived.
    Archived,
}

impl DomainEvent for OrganizationEvent {
    fn event_type(&self) -> &'static str {
        match self {
            Self::Created { .. } => "auth.organization.created",
            Self::OwnerAdded { .. } => "auth.organization.owner-added",
            Self::OwnerRemoved { .. } => "auth.organization.owner-removed",
            Self::Archived => "auth.organization.archived",
        }
    }
}

/// Event-sourced organization state.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct OrganizationAggregate {
    organization_id: Option<OrganizationId>,
    name: Option<String>,
    owners: BTreeSet<UserId>,
    archived: bool,
    revision: u64,
}

impl Aggregate for OrganizationAggregate {
    type Id = OrganizationId;
    type Command = OrganizationCommand;
    type Event = OrganizationEvent;
    type Error = DddAuthError;

    fn aggregate_type() -> &'static str {
        "auth_organization"
    }

    fn revision(&self) -> u64 {
        self.revision
    }

    fn apply(&mut self, event: &Self::Event) {
        match event {
            OrganizationEvent::Created {
                organization_id,
                owner_id,
                name,
            } => {
                self.organization_id = Some(organization_id.clone());
                self.name = Some(name.clone());
                self.owners.insert(owner_id.clone());
            }
            OrganizationEvent::OwnerAdded { user_id } => {
                self.owners.insert(user_id.clone());
            }
            OrganizationEvent::OwnerRemoved { user_id } => {
                self.owners.remove(user_id);
            }
            OrganizationEvent::Archived => self.archived = true,
        }
        self.revision += 1;
    }

    fn handle(&self, command: Self::Command) -> Result<Vec<Self::Event>, Self::Error> {
        match command {
            OrganizationCommand::Create {
                organization_id,
                owner_id,
                name,
            } => {
                if self.organization_id.is_some() {
                    return Err(DddAuthError::AlreadyExists);
                }
                if name.trim() != name || name.is_empty() {
                    return Err(DddAuthError::Invariant);
                }
                Ok(vec![OrganizationEvent::Created {
                    organization_id,
                    owner_id,
                    name,
                }])
            }
            OrganizationCommand::AddOwner { user_id } => {
                self.ensure_active()?;
                if self.owners.contains(&user_id) {
                    Ok(Vec::new())
                } else {
                    Ok(vec![OrganizationEvent::OwnerAdded { user_id }])
                }
            }
            OrganizationCommand::RemoveOwner { user_id } => {
                self.ensure_active()?;
                if self.owners.contains(&user_id) && self.owners.len() == 1 {
                    return Err(DddAuthError::Invariant);
                }
                if self.owners.contains(&user_id) {
                    Ok(vec![OrganizationEvent::OwnerRemoved { user_id }])
                } else {
                    Ok(Vec::new())
                }
            }
            OrganizationCommand::Archive => {
                self.ensure_exists()?;
                if self.archived {
                    Ok(Vec::new())
                } else {
                    Ok(vec![OrganizationEvent::Archived])
                }
            }
        }
    }

    fn new() -> Self {
        Self::default()
    }
}

impl OrganizationAggregate {
    fn ensure_exists(&self) -> Result<(), DddAuthError> {
        if self.organization_id.is_some() {
            Ok(())
        } else {
            Err(DddAuthError::NotFound)
        }
    }

    fn ensure_active(&self) -> Result<(), DddAuthError> {
        self.ensure_exists()?;
        if self.archived {
            Err(DddAuthError::Invariant)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn credential_event_does_not_contain_secret_material() {
        let event = UserEvent::CredentialLinked {
            credential_id: CredentialId::new("credential-one").expect("valid fixture"),
            secret_version: 1,
        };

        let json = serde_json::to_string(&event).expect("fixture serializes");

        assert!(!json.contains("password"));
    }
}
