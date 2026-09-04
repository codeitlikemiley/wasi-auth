//! Native PostgreSQL migration runner shared by release tooling and consumers.

use std::collections::BTreeSet;

use serde::Serialize;
use thiserror::Error;
use tokio_postgres::{Client, NoTls};

use super::{
    AppliedSchemaMigration, SchemaMigration, SchemaMigrationMode, SchemaPlanError, plan_schema,
};

const MIGRATION_ADVISORY_LOCK: i64 = 0x7761_7369_6175_7468;

/// Required tables in the production relational kernel.
pub const REQUIRED_RELATIONAL_TABLES: &[&str] = &[
    "auth_audit_log",
    "auth_application_redirects",
    "auth_external_identities",
    "auth_flows",
    "auth_idempotency",
    "auth_invitations",
    "auth_memberships",
    "auth_one_time_tokens",
    "auth_organizations",
    "auth_outbox",
    "auth_passkeys",
    "auth_passwords",
    "auth_policy_bundles",
    "auth_provider_configs",
    "auth_rate_limit_buckets",
    "auth_recovery_codes",
    "auth_redirect_uris",
    "auth_refresh_tokens",
    "auth_role_permissions",
    "auth_roles",
    "auth_schema_migrations",
    "auth_sessions",
    "auth_signing_keys",
    "auth_system_administrators",
    "auth_totp_factors",
    "auth_users",
];

/// Native schema administration operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum MigrationAction {
    /// Report pending migration versions without changing the database.
    Plan,
    /// Apply every pending migration while holding the advisory lock.
    Apply,
    /// Validate migration history and checksums.
    Verify,
    /// Validate history plus required relational-kernel tables.
    VerifyDatabase,
    /// Emit the current applied and pending version summary.
    Status,
}

/// Machine-readable migration operation result.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct MigrationReport {
    /// Applied versions present after the operation.
    pub applied: Vec<String>,
    /// Versions still pending after the operation.
    pub pending: Vec<String>,
    /// Whether required schema objects were verified.
    pub database_verified: bool,
}

/// Result of one bounded organization-slug backfill batch.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub struct OrganizationSlugBackfillReport {
    /// Rows updated by this invocation.
    pub updated: u64,
    /// Rows that still require a slug after this invocation.
    pub remaining: u64,
}

/// Lock-protected PostgreSQL migration runner.
#[derive(Debug, Default)]
pub struct MigrationRunner;

impl MigrationRunner {
    /// Runs one migration operation against a PostgreSQL URL.
    ///
    /// The URL is borrowed and never retained or included in debug/error text.
    ///
    /// # Errors
    ///
    /// Returns connection, history, lock, migration, or schema verification
    /// failures. Applied checksums are inserted only inside the transaction
    /// that successfully applied their migration.
    pub async fn run(
        database_url: &str,
        action: MigrationAction,
    ) -> Result<MigrationReport, MigrationRunnerError> {
        if database_url.is_empty()
            || database_url.len() > 4_096
            || database_url.chars().any(char::is_control)
        {
            return Err(MigrationRunnerError::InvalidDatabaseUrl);
        }
        let (mut client, connection) = tokio_postgres::connect(database_url, NoTls).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });

        match action {
            MigrationAction::Apply => apply(&mut client).await,
            MigrationAction::Plan | MigrationAction::Verify | MigrationAction::Status => {
                report(&client, false).await
            }
            MigrationAction::VerifyDatabase => report(&client, true).await,
        }
    }

    /// Backfills at most `batch_size` organization slugs using row skipping.
    ///
    /// Invoke repeatedly until [`OrganizationSlugBackfillReport::remaining`]
    /// reaches zero. Parallel invocations do not wait on rows already locked by
    /// another backfill worker.
    ///
    /// # Errors
    ///
    /// Returns validation, connection, or PostgreSQL failures. Migration 0011
    /// must already be applied.
    pub async fn backfill_organization_slugs(
        database_url: &str,
        batch_size: u32,
    ) -> Result<OrganizationSlugBackfillReport, MigrationRunnerError> {
        if database_url.is_empty()
            || database_url.len() > 4_096
            || database_url.chars().any(char::is_control)
        {
            return Err(MigrationRunnerError::InvalidDatabaseUrl);
        }
        if batch_size == 0 || batch_size > 5_000 {
            return Err(MigrationRunnerError::InvalidBatchSize);
        }
        let (mut client, connection) = tokio_postgres::connect(database_url, NoTls).await?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        let transaction = client.transaction().await?;
        let rows = transaction
            .query(
                "WITH batch AS (\
                     SELECT organization_id, name \
                     FROM auth_organizations \
                     WHERE slug IS NULL OR btrim(slug) = '' \
                     ORDER BY created_at_ms, organization_id \
                     FOR UPDATE SKIP LOCKED \
                     LIMIT $1\
                 ) \
                 UPDATE auth_organizations AS organizations \
                 SET slug = auth_default_organization_slug(batch.name, batch.organization_id), \
                     updated_at_ms = (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint \
                 FROM batch \
                 WHERE organizations.organization_id = batch.organization_id \
                 RETURNING organizations.organization_id",
                &[&i64::from(batch_size)],
            )
            .await?;
        transaction.commit().await?;
        let remaining: i64 = client
            .query_one(
                "SELECT count(*) FROM auth_organizations WHERE slug IS NULL OR btrim(slug) = ''",
                &[],
            )
            .await?
            .get(0);
        Ok(OrganizationSlugBackfillReport {
            updated: rows.len() as u64,
            remaining: u64::try_from(remaining).unwrap_or(u64::MAX),
        })
    }
}

async fn apply(client: &mut Client) -> Result<MigrationReport, MigrationRunnerError> {
    client
        .query_one("SELECT pg_advisory_lock($1)", &[&MIGRATION_ADVISORY_LOCK])
        .await?;
    let result = apply_locked(client).await;
    let unlock = client
        .query_one("SELECT pg_advisory_unlock($1)", &[&MIGRATION_ADVISORY_LOCK])
        .await;
    match (result, unlock) {
        (Ok(report), Ok(_)) => Ok(report),
        (Err(error), _) => Err(error),
        (Ok(_), Err(error)) => Err(MigrationRunnerError::Postgres(error)),
    }
}

async fn apply_locked(client: &mut Client) -> Result<MigrationReport, MigrationRunnerError> {
    let applied = load_applied(client).await?;
    let pending = plan_schema(&applied)?;
    for migration in pending {
        match migration.mode() {
            SchemaMigrationMode::Transactional => apply_transactional(client, migration).await?,
            SchemaMigrationMode::Autocommit => apply_autocommit(client, migration).await?,
        }
    }
    report(client, true).await
}

async fn apply_transactional(
    client: &mut Client,
    migration: SchemaMigration,
) -> Result<(), MigrationRunnerError> {
    let transaction = client.transaction().await?;
    transaction.batch_execute(migration.sql()).await?;
    record_migration(&transaction, migration).await?;
    transaction.commit().await?;
    Ok(())
}

async fn apply_autocommit(
    client: &mut Client,
    migration: SchemaMigration,
) -> Result<(), MigrationRunnerError> {
    client.batch_execute(migration.sql()).await?;
    verify_autocommit_postcondition(client, migration).await?;
    let transaction = client.transaction().await?;
    record_migration(&transaction, migration).await?;
    transaction.commit().await?;
    Ok(())
}

async fn record_migration(
    transaction: &tokio_postgres::Transaction<'_>,
    migration: SchemaMigration,
) -> Result<(), tokio_postgres::Error> {
    transaction
        .execute(
            "INSERT INTO auth_schema_migrations (version, checksum, applied_at_ms) \
             VALUES ($1, $2, (EXTRACT(EPOCH FROM clock_timestamp()) * 1000)::bigint)",
            &[&migration.version(), &migration.checksum_hex()],
        )
        .await?;
    Ok(())
}

async fn verify_autocommit_postcondition(
    client: &Client,
    migration: SchemaMigration,
) -> Result<(), MigrationRunnerError> {
    if migration.version() != "0012_organization_slug_unique_index" {
        return Err(MigrationRunnerError::UnsupportedAutocommitMigration(
            migration.version().to_owned(),
        ));
    }
    let row = client
        .query_opt(
            "SELECT indexes.indisvalid, indexes.indisready, indexes.indisunique, \
                    pg_get_indexdef(classes.oid), \
                    pg_get_expr(indexes.indpred, indexes.indrelid) \
             FROM pg_class AS classes \
             JOIN pg_namespace AS namespaces ON namespaces.oid = classes.relnamespace \
             JOIN pg_index AS indexes ON indexes.indexrelid = classes.oid \
             WHERE namespaces.nspname = 'public' \
               AND classes.relname = 'auth_organizations_slug_uidx'",
            &[],
        )
        .await?
        .ok_or_else(|| {
            MigrationRunnerError::InvalidMigrationPostcondition(migration.version().to_owned())
        })?;
    let valid: bool = row.get(0);
    let ready: bool = row.get(1);
    let unique: bool = row.get(2);
    let definition: String = row.get(3);
    let predicate: Option<String> = row.get(4);
    let expected_definition = "CREATE UNIQUE INDEX auth_organizations_slug_uidx ON public.auth_organizations USING btree (slug) WHERE (slug IS NOT NULL)";
    if !valid
        || !ready
        || !unique
        || definition != expected_definition
        || predicate.as_deref() != Some("(slug IS NOT NULL)")
    {
        return Err(MigrationRunnerError::InvalidMigrationPostcondition(
            migration.version().to_owned(),
        ));
    }
    Ok(())
}

async fn report(
    client: &Client,
    verify_database: bool,
) -> Result<MigrationReport, MigrationRunnerError> {
    let applied = load_applied(client).await?;
    let pending = plan_schema(&applied)?;
    let database_verified = if verify_database {
        if !pending.is_empty() {
            return Err(MigrationRunnerError::PendingMigrations);
        }
        verify_tables(client).await?;
        true
    } else {
        false
    };
    Ok(MigrationReport {
        applied: applied
            .into_iter()
            .map(|migration| migration.version)
            .collect(),
        pending: pending
            .into_iter()
            .map(|migration| migration.version().to_owned())
            .collect(),
        database_verified,
    })
}

async fn load_applied(
    client: &Client,
) -> Result<Vec<AppliedSchemaMigration>, MigrationRunnerError> {
    let exists: bool = client
        .query_one(
            "SELECT to_regclass('public.auth_schema_migrations') IS NOT NULL",
            &[],
        )
        .await?
        .get(0);
    if !exists {
        return Ok(Vec::new());
    }
    client
        .query(
            "SELECT version, checksum FROM auth_schema_migrations ORDER BY version",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| {
            Ok(AppliedSchemaMigration {
                version: row.try_get("version")?,
                checksum: row.try_get("checksum")?,
            })
        })
        .collect()
}

async fn verify_tables(client: &Client) -> Result<(), MigrationRunnerError> {
    let actual = client
        .query(
            "SELECT table_name FROM information_schema.tables \
             WHERE table_schema = current_schema() AND table_name LIKE 'auth_%'",
            &[],
        )
        .await?
        .into_iter()
        .map(|row| row.get::<_, String>(0))
        .collect::<BTreeSet<_>>();
    let missing = REQUIRED_RELATIONAL_TABLES
        .iter()
        .filter(|table| !actual.contains(**table))
        .copied()
        .collect::<Vec<_>>();
    if missing.is_empty() {
        Ok(())
    } else {
        Err(MigrationRunnerError::MissingTables(missing.join(",")))
    }
}

/// Native migration runner failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MigrationRunnerError {
    /// Database URL failed bounded validation.
    #[error("PostgreSQL migration URL is invalid")]
    InvalidDatabaseUrl,
    /// A bounded maintenance command received an invalid batch size.
    #[error("migration batch size must be between 1 and 5000")]
    InvalidBatchSize,
    /// PostgreSQL operation failed.
    #[error("PostgreSQL migration operation failed: {0}")]
    Postgres(#[from] tokio_postgres::Error),
    /// Migration history failed closed validation.
    #[error(transparent)]
    Plan(#[from] SchemaPlanError),
    /// Database verification was requested before all migrations were applied.
    #[error("database has pending migrations")]
    PendingMigrations,
    /// An autocommit migration lacks a fail-closed verifier.
    #[error("unsupported autocommit migration {0}")]
    UnsupportedAutocommitMigration(String),
    /// An autocommit migration did not create the exact expected object.
    #[error("migration postcondition failed for {0}")]
    InvalidMigrationPostcondition(String),
    /// Required relational-kernel tables are absent.
    #[error("database is missing required tables: {0}")]
    MissingTables(String),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expected_schema_has_no_legacy_event_tables() {
        assert!(!REQUIRED_RELATIONAL_TABLES.contains(&"auth_events"));
        assert!(!REQUIRED_RELATIONAL_TABLES.contains(&"auth_projection_records"));
        assert!(!REQUIRED_RELATIONAL_TABLES.contains(&"events"));
    }
}
