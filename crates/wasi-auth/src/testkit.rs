//! Deterministic test fixtures that are never part of the production feature set.

/// Former DDD in-memory evaluator retained only for deterministic tests.
#[cfg(feature = "testkit-evaluator")]
#[allow(clippy::enum_variant_names, dead_code, missing_docs, unused_imports)]
pub mod evaluator;

use std::collections::{BTreeMap, BTreeSet};
use std::convert::Infallible;
use std::future::{Future, ready};
use std::sync::Mutex;

use thiserror::Error;

use crate::authentication::{
    AuthMutation, AuthUnitOfWork, CommitReceipt, OutboxIntent, ProjectionMutation, SanitizedEvent,
    SecretMutation,
};
use crate::authorization::{AccessRequest, Decision, DecisionProvider, ProviderCapabilities};
use crate::context::{
    AuthenticationAssurance, ContextError, CredentialId, OrganizationId, PolicyRevision, Principal,
    RequestId, SessionId, UserId, ValidatedContextParts, VerifiedAuthContext,
};
use crate::mail::EmailKind;

/// Builder for a verified context in tests.
///
/// Production code cannot construct [`VerifiedAuthContext`] directly.
#[derive(Clone, Debug)]
pub struct VerifiedAuthContextBuilder {
    user_id: String,
    issuer: String,
    organization_id: Option<String>,
    session_id: String,
    request_id: String,
    assurance: AuthenticationAssurance,
    system_administrator: bool,
    issued_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
}

impl VerifiedAuthContextBuilder {
    /// Creates a deterministic authenticated fixture.
    #[must_use]
    pub fn new() -> Self {
        Self {
            user_id: "user-one".to_owned(),
            issuer: "https://identity.example.test".to_owned(),
            organization_id: Some("organization-one".to_owned()),
            session_id: "session-one".to_owned(),
            request_id: "request-one".to_owned(),
            assurance: AuthenticationAssurance::Aal1,
            system_administrator: false,
            issued_at_unix_seconds: 1_000,
            expires_at_unix_seconds: 2_000,
        }
    }

    /// Overrides the user identifier.
    #[must_use]
    pub fn user_id(mut self, value: impl Into<String>) -> Self {
        self.user_id = value.into();
        self
    }

    /// Overrides the identity issuer.
    #[must_use]
    pub fn issuer(mut self, value: impl Into<String>) -> Self {
        self.issuer = value.into();
        self
    }

    /// Overrides the selected organization.
    #[must_use]
    pub fn organization_id(mut self, value: impl Into<String>) -> Self {
        self.organization_id = Some(value.into());
        self
    }

    /// Removes tenant selection from the fixture.
    #[must_use]
    pub fn without_organization(mut self) -> Self {
        self.organization_id = None;
        self
    }

    /// Marks the fixture as a system administrator.
    #[must_use]
    pub fn system_administrator(mut self) -> Self {
        self.system_administrator = true;
        self
    }

    /// Sets MFA-level assurance.
    #[must_use]
    pub fn step_up(mut self) -> Self {
        self.assurance = AuthenticationAssurance::Aal2;
        self
    }

    /// Builds the verified fixture.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] if an overridden value violates the production
    /// context contract.
    pub fn build(self) -> Result<VerifiedAuthContext, ContextError> {
        let principal = Principal::new(
            UserId::new(self.user_id)?,
            self.issuer,
            self.system_administrator,
        )?;
        VerifiedAuthContext::from_validated(ValidatedContextParts {
            principal,
            organization_id: self.organization_id.map(OrganizationId::new).transpose()?,
            session_id: SessionId::new(self.session_id)?,
            request_id: RequestId::new(self.request_id)?,
            assurance: self.assurance,
            issued_at_unix_seconds: self.issued_at_unix_seconds,
            expires_at_unix_seconds: self.expires_at_unix_seconds,
            decision_id: None,
            policy_revision: None,
        })
    }
}

impl Default for VerifiedAuthContextBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Exact in-memory authorization rule for unit tests.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct InMemoryRule {
    user_id: UserId,
    organization_id: Option<OrganizationId>,
    action: String,
    resource_type: String,
    resource_id: String,
}

impl InMemoryRule {
    /// Creates an exact allow rule from validated identifiers.
    #[must_use]
    pub fn new(
        user_id: UserId,
        organization_id: Option<OrganizationId>,
        action: impl Into<String>,
        resource_type: impl Into<String>,
        resource_id: impl Into<String>,
    ) -> Self {
        Self {
            user_id,
            organization_id,
            action: action.into(),
            resource_type: resource_type.into(),
            resource_id: resource_id.into(),
        }
    }
}

/// Linear in-memory evaluator retained only for tests and examples.
#[derive(Clone, Debug)]
pub struct InMemoryDecisionProvider {
    rules: BTreeSet<InMemoryRule>,
    policy_revision: PolicyRevision,
}

impl InMemoryDecisionProvider {
    /// Creates a test provider from exact allow rules.
    ///
    /// # Errors
    ///
    /// Returns [`ContextError`] when the fixture policy revision is invalid.
    pub fn new(rules: impl IntoIterator<Item = InMemoryRule>) -> Result<Self, ContextError> {
        Ok(Self {
            rules: rules.into_iter().collect(),
            policy_revision: PolicyRevision::new("testkit-in-memory-v1")?,
        })
    }
}

impl DecisionProvider for InMemoryDecisionProvider {
    type Error = Infallible;

    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities::default()
    }

    fn check<'a>(
        &'a self,
        request: &'a AccessRequest,
    ) -> impl Future<Output = Result<Decision, Self::Error>> + Send + 'a {
        let rule = InMemoryRule::new(
            request.context().principal().user_id().clone(),
            request.resource().organization_id().cloned(),
            request.action().as_str(),
            request.resource().resource_type().as_str(),
            request.resource().id(),
        );
        let decision = if self.rules.contains(&rule) {
            Decision::allow(self.policy_revision.clone(), "testkit.allow")
        } else {
            Decision::deny(self.policy_revision.clone(), "testkit.deny")
        };
        ready(Ok(decision))
    }
}

/// Commit phase at which [`AtomicTestUnitOfWork`] can inject a rollback.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CommitStage {
    /// After staging immutable events.
    Events,
    /// After staging projections.
    Projections,
    /// After staging secret-vault changes.
    Secrets,
    /// After staging durable outbox intents.
    Outbox,
}

/// Deterministic atomic-store failure.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
#[non_exhaustive]
pub enum AtomicTestStoreError {
    /// The test requested a rollback at a particular phase.
    #[error("atomic test store injected a rollback at {0:?}")]
    Injected(CommitStage),
    /// A test poisoned the state lock.
    #[error("atomic test store lock is unavailable")]
    LockUnavailable,
    /// An idempotency key was reused for a different operation or request.
    #[error("idempotency key conflicts with an earlier request")]
    IdempotencyConflict,
}

/// Redacted durable outbox record visible to assertions.
#[derive(Clone, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum CapturedOutboxIntent {
    /// Mail metadata with the recipient and body intentionally omitted.
    Mail {
        /// Typed message category.
        kind: EmailKind,
        /// Non-secret request correlation identifier.
        correlation_id: String,
    },
    /// Relationship synchronization metadata.
    Relationship(crate::authentication::RelationshipOutboxIntent),
}

#[derive(Clone, Debug, Default)]
struct AtomicTestState {
    revision: u64,
    receipts: BTreeMap<String, StoredReceipt>,
    events: Vec<SanitizedEvent>,
    projections: Vec<ProjectionMutation>,
    secrets: BTreeMap<String, Vec<u8>>,
    outbox: Vec<CapturedOutboxIntent>,
}

#[derive(Clone, Debug)]
struct StoredReceipt {
    operation: String,
    request_hash: [u8; 32],
    receipt: CommitReceipt,
}

/// Redacted snapshot of an [`AtomicTestUnitOfWork`].
#[derive(Clone, Debug, Default)]
pub struct AtomicTestSnapshot {
    state: AtomicTestState,
}

impl AtomicTestSnapshot {
    /// Returns the committed revision.
    #[must_use]
    pub const fn revision(&self) -> u64 {
        self.state.revision
    }

    /// Returns committed sanitized events.
    #[must_use]
    pub fn events(&self) -> &[SanitizedEvent] {
        &self.state.events
    }

    /// Returns committed projection changes.
    #[must_use]
    pub fn projections(&self) -> &[ProjectionMutation] {
        &self.state.projections
    }

    /// Returns whether a secret exists without exposing it in debug output.
    #[must_use]
    pub fn contains_secret(&self, credential_id: &CredentialId) -> bool {
        self.state.secrets.contains_key(credential_id.as_str())
    }

    /// Returns committed, redacted outbox metadata.
    #[must_use]
    pub fn outbox(&self) -> &[CapturedOutboxIntent] {
        &self.state.outbox
    }
}

/// In-memory transaction boundary for atomicity and idempotency contract tests.
///
/// It stages a complete copy and swaps it into place only after every phase
/// succeeds, which makes injected failures useful for proving rollback.
#[derive(Debug, Default)]
pub struct AtomicTestUnitOfWork {
    state: Mutex<AtomicTestState>,
    fail_next: Mutex<Option<CommitStage>>,
}

impl AtomicTestUnitOfWork {
    /// Injects one failure after the selected stage has been staged.
    ///
    /// # Errors
    ///
    /// Returns [`AtomicTestStoreError::LockUnavailable`] if the control lock
    /// was poisoned.
    pub fn fail_next_at(&self, stage: CommitStage) -> Result<(), AtomicTestStoreError> {
        let mut fail_next = self
            .fail_next
            .lock()
            .map_err(|_| AtomicTestStoreError::LockUnavailable)?;
        *fail_next = Some(stage);
        Ok(())
    }

    /// Returns a redacted store snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`AtomicTestStoreError::LockUnavailable`] if the state lock was
    /// poisoned.
    pub fn snapshot(&self) -> Result<AtomicTestSnapshot, AtomicTestStoreError> {
        self.state
            .lock()
            .map(|state| AtomicTestSnapshot {
                state: state.clone(),
            })
            .map_err(|_| AtomicTestStoreError::LockUnavailable)
    }

    fn fail_if_requested(&self, stage: CommitStage) -> Result<(), AtomicTestStoreError> {
        let mut fail_next = self
            .fail_next
            .lock()
            .map_err(|_| AtomicTestStoreError::LockUnavailable)?;
        if *fail_next == Some(stage) {
            *fail_next = None;
            Err(AtomicTestStoreError::Injected(stage))
        } else {
            Ok(())
        }
    }
}

impl AuthUnitOfWork for AtomicTestUnitOfWork {
    type Error = AtomicTestStoreError;

    async fn commit(&self, mutation: &AuthMutation) -> Result<CommitReceipt, Self::Error> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| AtomicTestStoreError::LockUnavailable)?;
        if let Some(stored) = state.receipts.get(mutation.idempotency_key().as_str()) {
            if stored.operation != mutation.operation()
                || stored.request_hash != *mutation.request_hash()
            {
                return Err(AtomicTestStoreError::IdempotencyConflict);
            }
            return Ok(CommitReceipt {
                revision: stored.receipt.revision,
                replayed: true,
            });
        }

        let mut staged = state.clone();
        staged.events.extend_from_slice(mutation.events());
        self.fail_if_requested(CommitStage::Events)?;

        staged.projections.extend_from_slice(mutation.projections());
        self.fail_if_requested(CommitStage::Projections)?;

        for secret in mutation.secrets() {
            match secret {
                SecretMutation::Put {
                    credential,
                    material,
                } => {
                    staged.secrets.insert(
                        credential.id.as_str().to_owned(),
                        material.expose().to_vec(),
                    );
                }
                SecretMutation::Delete { credential_id } => {
                    staged.secrets.remove(credential_id.as_str());
                }
            }
        }
        self.fail_if_requested(CommitStage::Secrets)?;

        staged
            .outbox
            .extend(mutation.outbox_intents().iter().map(|intent| match intent {
                OutboxIntent::Mail(message) => CapturedOutboxIntent::Mail {
                    kind: message.kind(),
                    correlation_id: message.correlation_id().to_owned(),
                },
                OutboxIntent::Relationship(relationship) => {
                    CapturedOutboxIntent::Relationship(relationship.clone())
                }
            }));
        self.fail_if_requested(CommitStage::Outbox)?;

        staged.revision = staged
            .revision
            .saturating_add(u64::try_from(mutation.events().len()).unwrap_or(u64::MAX));
        let receipt = CommitReceipt {
            revision: staged.revision,
            replayed: false,
        };
        staged.receipts.insert(
            mutation.idempotency_key().as_str().to_owned(),
            StoredReceipt {
                operation: mutation.operation().to_owned(),
                request_hash: *mutation.request_hash(),
                receipt: receipt.clone(),
            },
        );
        *state = staged;
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests {
    use futures::executor::block_on;

    use super::*;
    use crate::authentication::{
        CredentialDescriptor, CredentialKind, ProjectionKind, RelationshipOperation,
        RelationshipOutboxIntent, SecretMaterial,
    };
    use crate::context::IdempotencyKey;

    fn fixture_mutation() -> AuthMutation {
        let credential_id = CredentialId::new("credential-one").expect("valid fixture");
        let credential = CredentialDescriptor {
            id: credential_id,
            user_id: UserId::new("user-one").expect("valid fixture"),
            kind: CredentialKind::Password,
            secret_version: 1,
        };
        AuthMutation::new(
            IdempotencyKey::new("command-one").expect("valid fixture"),
            "auth.user.register",
            [7; 32],
            vec![SanitizedEvent {
                aggregate_type: "auth_user".to_owned(),
                aggregate_id: "user-one".to_owned(),
                expected_revision: 0,
                event_type: "auth.user.registered".to_owned(),
                payload_json: r#"{"user_id":"user-one"}"#.to_owned(),
            }],
            vec![ProjectionMutation::Upsert {
                projection: ProjectionKind::User,
                key: "user-one".to_owned(),
                value_json: r#"{"status":"pending"}"#.to_owned(),
            }],
            vec![SecretMutation::Put {
                credential,
                material: SecretMaterial::new(b"password-hash".to_vec()).expect("valid fixture"),
            }],
            vec![OutboxIntent::Relationship(RelationshipOutboxIntent {
                operation: RelationshipOperation::Grant,
                resource: "organization:one".to_owned(),
                relation: "owner".to_owned(),
                subject: "user:one".to_owned(),
                resource_revision: 1,
                consistency_token: None,
            })],
        )
        .expect("valid fixture")
    }

    #[test]
    fn injected_failure_rolls_back_every_staged_change() {
        let unit_of_work = AtomicTestUnitOfWork::default();
        unit_of_work
            .fail_next_at(CommitStage::Secrets)
            .expect("failure injection succeeds");

        let error =
            block_on(unit_of_work.commit(&fixture_mutation())).expect_err("commit must roll back");
        let snapshot = unit_of_work.snapshot().expect("snapshot succeeds");

        assert_eq!(error, AtomicTestStoreError::Injected(CommitStage::Secrets));
        assert_eq!(snapshot.revision(), 0);
        assert!(snapshot.events().is_empty());
        assert!(snapshot.projections().is_empty());
        assert!(snapshot.outbox().is_empty());
        assert!(
            !snapshot.contains_secret(&CredentialId::new("credential-one").expect("valid fixture"))
        );
    }

    #[test]
    fn successful_commit_replays_without_duplicate_side_effects() {
        let unit_of_work = AtomicTestUnitOfWork::default();
        let mutation = fixture_mutation();

        let committed = block_on(unit_of_work.commit(&mutation)).expect("commit succeeds");
        let replayed = block_on(unit_of_work.commit(&mutation)).expect("replay succeeds");
        let snapshot = unit_of_work.snapshot().expect("snapshot succeeds");

        assert_eq!(committed.revision, 1);
        assert!(!committed.replayed);
        assert_eq!(replayed.revision, committed.revision);
        assert!(replayed.replayed);
        assert_eq!(snapshot.events().len(), 1);
        assert_eq!(snapshot.projections().len(), 1);
        assert_eq!(snapshot.outbox().len(), 1);
        assert!(
            snapshot.contains_secret(&CredentialId::new("credential-one").expect("valid fixture"))
        );
    }

    #[test]
    fn mutation_debug_never_contains_secret_material() {
        let debug = format!("{:?}", fixture_mutation());

        assert!(!debug.contains("password-hash"));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn idempotency_key_reuse_with_a_different_request_fails_closed() {
        let unit_of_work = AtomicTestUnitOfWork::default();
        let first = fixture_mutation();
        block_on(unit_of_work.commit(&first)).expect("first commit succeeds");

        let conflicting = AuthMutation::new(
            IdempotencyKey::new("command-one").expect("valid fixture"),
            "auth.user.register",
            [8; 32],
            vec![SanitizedEvent {
                aggregate_type: "auth_user".to_owned(),
                aggregate_id: "user-one".to_owned(),
                expected_revision: 0,
                event_type: "auth.user.registered".to_owned(),
                payload_json: r#"{"user_id":"user-one"}"#.to_owned(),
            }],
            Vec::new(),
            Vec::new(),
            Vec::new(),
        )
        .expect("valid fixture");
        let error = block_on(unit_of_work.commit(&conflicting)).expect_err("conflict is rejected");

        assert_eq!(error, AtomicTestStoreError::IdempotencyConflict);
        assert_eq!(
            unit_of_work
                .snapshot()
                .expect("snapshot succeeds")
                .events()
                .len(),
            1
        );
    }
}
