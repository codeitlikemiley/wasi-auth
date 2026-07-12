//! CLI facade over the reusable `wasi-auth` PostgreSQL migration runner.

pub use wasi_auth::schema::native::{
    MigrationAction as MigrationCommand, MigrationReport,
    MigrationRunnerError as MigrationToolError,
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
            ]
        );
    }
}
