//! Immutable PostgreSQL schema catalog for the relational auth kernel.

use std::collections::{BTreeMap, BTreeSet};

use sha2::{Digest, Sha256};
use thiserror::Error;

#[cfg(feature = "postgres-native")]
pub mod native;

/// One immutable PostgreSQL migration embedded in the published crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SchemaMigration {
    version: &'static str,
    sql: &'static str,
}

impl SchemaMigration {
    /// Returns the ordered migration version.
    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }

    /// Returns the PostgreSQL migration document.
    #[must_use]
    pub const fn sql(self) -> &'static str {
        self.sql
    }

    /// Returns the lowercase SHA-256 source checksum.
    #[must_use]
    pub fn checksum_hex(self) -> String {
        Sha256::digest(self.sql.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Applied migration metadata loaded from PostgreSQL.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedSchemaMigration {
    /// Applied migration version.
    pub version: String,
    /// Persisted lowercase SHA-256 checksum.
    pub checksum: String,
}

/// Relational-kernel schema version 0001.
pub const POSTGRES_RELATIONAL_0001: SchemaMigration = SchemaMigration {
    version: "0001_relational_kernel",
    sql: include_str!("../migrations/postgres/0001_relational_kernel.sql"),
};

/// Relational-kernel outbox delivery receipt extension.
pub const POSTGRES_OUTBOX_0002: SchemaMigration = SchemaMigration {
    version: "0002_outbox_delivery_id",
    sql: include_str!("../migrations/postgres/0002_outbox_delivery_id.sql"),
};

/// Organization-management integrity and stable audit cursor extension.
pub const POSTGRES_MANAGEMENT_0003: SchemaMigration = SchemaMigration {
    version: "0003_management_integrity",
    sql: include_str!("../migrations/postgres/0003_management_integrity.sql"),
};

/// Database-enforced active-organization owner invariant.
pub const POSTGRES_OWNER_INVARIANT_0004: SchemaMigration = SchemaMigration {
    version: "0004_owner_invariant",
    sql: include_str!("../migrations/postgres/0004_owner_invariant.sql"),
};

/// Owner-trigger authorization-revision integration and existing-data guard.
pub const POSTGRES_OWNER_TRIGGER_0005: SchemaMigration = SchemaMigration {
    version: "0005_owner_trigger_revision",
    sql: include_str!("../migrations/postgres/0005_owner_trigger_revision.sql"),
};

/// OAuth provider defaults and exact application redirect allowlist.
pub const POSTGRES_OAUTH_DEFAULTS_0006: SchemaMigration = SchemaMigration {
    version: "0006_oauth_provider_defaults",
    sql: include_str!("../migrations/postgres/0006_oauth_provider_defaults.sql"),
};

/// Signing-key lifecycle metadata backed by external secret references.
pub const POSTGRES_SIGNING_KEYS_0007: SchemaMigration = SchemaMigration {
    version: "0007_signing_key_references",
    sql: include_str!("../migrations/postgres/0007_signing_key_references.sql"),
};

/// Canonical fullstack account and dashboard redirect paths.
pub const POSTGRES_FULLSTACK_REDIRECTS_0008: SchemaMigration = SchemaMigration {
    version: "0008_fullstack_redirects",
    sql: include_str!("../migrations/postgres/0008_fullstack_redirects.sql"),
};

/// Transactional PostgreSQL notifications for native-ingress cache safety.
pub const POSTGRES_CONTEXT_INVALIDATION_0009: SchemaMigration = SchemaMigration {
    version: "0009_context_invalidation",
    sql: include_str!("../migrations/postgres/0009_context_invalidation.sql"),
};

/// Returns the complete ordered relational-kernel migration catalog.
#[must_use]
pub const fn schema_migrations() -> &'static [SchemaMigration] {
    &[
        POSTGRES_RELATIONAL_0001,
        POSTGRES_OUTBOX_0002,
        POSTGRES_MANAGEMENT_0003,
        POSTGRES_OWNER_INVARIANT_0004,
        POSTGRES_OWNER_TRIGGER_0005,
        POSTGRES_OAUTH_DEFAULTS_0006,
        POSTGRES_SIGNING_KEYS_0007,
        POSTGRES_FULLSTACK_REDIRECTS_0008,
        POSTGRES_CONTEXT_INVALIDATION_0009,
    ]
}

/// Validates applied history and returns the pending suffix.
///
/// # Errors
///
/// Rejects duplicate, unknown, drifted, or gapped migration histories.
pub fn plan_schema(
    applied: &[AppliedSchemaMigration],
) -> Result<Vec<SchemaMigration>, SchemaPlanError> {
    let known = schema_migrations()
        .iter()
        .map(|migration| (migration.version(), *migration))
        .collect::<BTreeMap<_, _>>();
    let mut seen = BTreeSet::new();
    for migration in applied {
        if !seen.insert(migration.version.as_str()) {
            return Err(SchemaPlanError::DuplicateVersion(migration.version.clone()));
        }
        let Some(expected) = known.get(migration.version.as_str()) else {
            return Err(SchemaPlanError::UnknownVersion(migration.version.clone()));
        };
        if migration.checksum != expected.checksum_hex() {
            return Err(SchemaPlanError::ChecksumDrift(migration.version.clone()));
        }
    }
    for expected in schema_migrations().iter().take(applied.len()) {
        if !seen.contains(expected.version()) {
            return Err(SchemaPlanError::Gap(expected.version().to_owned()));
        }
    }
    Ok(schema_migrations()[applied.len()..].to_vec())
}

/// Schema-history validation failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum SchemaPlanError {
    /// Applied version is unknown to this binary.
    #[error("database contains unknown future migration {0}")]
    UnknownVersion(String),
    /// Applied source checksum differs from the immutable catalog.
    #[error("checksum drift detected for migration {0}")]
    ChecksumDrift(String),
    /// Applied history omitted an earlier migration.
    #[error("migration gap detected before {0}")]
    Gap(String),
    /// Applied history contains a version more than once.
    #[error("duplicate applied migration {0}")]
    DuplicateVersion(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_database_plans_complete_schema() {
        assert_eq!(
            plan_schema(&[]),
            Ok(vec![
                POSTGRES_RELATIONAL_0001,
                POSTGRES_OUTBOX_0002,
                POSTGRES_MANAGEMENT_0003,
                POSTGRES_OWNER_INVARIANT_0004,
                POSTGRES_OWNER_TRIGGER_0005,
                POSTGRES_OAUTH_DEFAULTS_0006,
                POSTGRES_SIGNING_KEYS_0007,
                POSTGRES_FULLSTACK_REDIRECTS_0008,
                POSTGRES_CONTEXT_INVALIDATION_0009,
            ])
        );
    }

    #[test]
    fn matching_database_has_no_pending_migrations() {
        let applied = [
            AppliedSchemaMigration {
                version: POSTGRES_RELATIONAL_0001.version().to_owned(),
                checksum: POSTGRES_RELATIONAL_0001.checksum_hex(),
            },
            AppliedSchemaMigration {
                version: POSTGRES_OUTBOX_0002.version().to_owned(),
                checksum: POSTGRES_OUTBOX_0002.checksum_hex(),
            },
            AppliedSchemaMigration {
                version: POSTGRES_MANAGEMENT_0003.version().to_owned(),
                checksum: POSTGRES_MANAGEMENT_0003.checksum_hex(),
            },
            AppliedSchemaMigration {
                version: POSTGRES_OWNER_INVARIANT_0004.version().to_owned(),
                checksum: POSTGRES_OWNER_INVARIANT_0004.checksum_hex(),
            },
            AppliedSchemaMigration {
                version: POSTGRES_OWNER_TRIGGER_0005.version().to_owned(),
                checksum: POSTGRES_OWNER_TRIGGER_0005.checksum_hex(),
            },
            AppliedSchemaMigration {
                version: POSTGRES_OAUTH_DEFAULTS_0006.version().to_owned(),
                checksum: POSTGRES_OAUTH_DEFAULTS_0006.checksum_hex(),
            },
            AppliedSchemaMigration {
                version: POSTGRES_SIGNING_KEYS_0007.version().to_owned(),
                checksum: POSTGRES_SIGNING_KEYS_0007.checksum_hex(),
            },
            AppliedSchemaMigration {
                version: POSTGRES_FULLSTACK_REDIRECTS_0008.version().to_owned(),
                checksum: POSTGRES_FULLSTACK_REDIRECTS_0008.checksum_hex(),
            },
            AppliedSchemaMigration {
                version: POSTGRES_CONTEXT_INVALIDATION_0009.version().to_owned(),
                checksum: POSTGRES_CONTEXT_INVALIDATION_0009.checksum_hex(),
            },
        ];

        assert_eq!(plan_schema(&applied), Ok(Vec::new()));
    }

    #[test]
    fn changed_source_is_rejected() {
        let applied = [AppliedSchemaMigration {
            version: POSTGRES_RELATIONAL_0001.version().to_owned(),
            checksum: "00".repeat(32),
        }];

        assert!(matches!(
            plan_schema(&applied),
            Err(SchemaPlanError::ChecksumDrift(_))
        ));
    }

    #[test]
    fn relational_schema_excludes_legacy_event_and_sqlite_models() {
        let sql = POSTGRES_RELATIONAL_0001.sql();
        assert!(!sql.contains("CREATE TABLE events"));
        assert!(!sql.contains("auth_events"));
        assert!(!sql.contains("auth_projection_records"));
        assert!(!sql.contains("auth_membership_roles"));
        assert!(!sql.contains("auth_redirect_allowlists"));
        assert!(sql.contains("CREATE TABLE auth_outbox"));
        assert!(sql.contains("CREATE TABLE auth_audit_log"));
    }
}
