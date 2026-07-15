//! CLI facade over the reusable `wasi-auth` PostgreSQL migration runner.

pub use wasi_auth::schema::native::{
    MigrationAction as MigrationCommand, MigrationReport,
    MigrationRunnerError as MigrationToolError, OrganizationSlugBackfillReport,
};
use wasi_auth::schema::{native::MigrationRunner, schema_migrations};

/// Runs one migration administration command.
///
/// # Errors
///
/// Returns connection, history, migration, lock, or schema verification
/// failures from the reusable migration runner.
pub async fn run(
    database_url: &str,
    command: MigrationCommand,
) -> Result<MigrationReport, MigrationToolError> {
    MigrationRunner::run(database_url, command).await
}

/// Backfills one bounded batch of missing organization slugs.
///
/// # Errors
///
/// Returns validation, connection, or PostgreSQL failures from the reusable
/// migration runner.
pub async fn backfill_organization_slugs(
    database_url: &str,
    batch_size: u32,
) -> Result<OrganizationSlugBackfillReport, MigrationToolError> {
    MigrationRunner::backfill_organization_slugs(database_url, batch_size).await
}

/// Returns the immutable migration versions bundled with this binary.
#[must_use]
pub fn catalog_versions() -> Vec<&'static str> {
    schema_migrations()
        .iter()
        .map(|migration| migration.version())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_the_relational_catalog() {
        assert_eq!(
            catalog_versions(),
            vec![
                "0001_relational_kernel",
                "0002_outbox_delivery_id",
                "0003_management_integrity",
                "0004_owner_invariant",
                "0005_owner_trigger_revision",
                "0006_oauth_provider_defaults",
                "0007_signing_key_references",
                "0008_fullstack_redirects",
                "0009_context_invalidation",
                "0010_typed_relationship_outbox",
                "0011_organization_slug_expand",
                "0012_organization_slug_unique_index",
                "0013_fullstack_permissions",
            ]
        );
    }
}
