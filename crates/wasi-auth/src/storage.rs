//! Authoritative authentication storage migrations.
//!
//! PostgreSQL is the production authority. Spin SQLite mirrors the same table
//! and column contract for local development. Runtime adapters must execute a
//! migration as one database transaction and record its computed checksum in
//! `auth_schema_migrations` only after the transaction commits.

use std::{collections::BTreeMap, error::Error as StdError, future::Future};

use sha2::{Digest, Sha256};
use thiserror::Error;

/// Supported durable authentication storage dialect.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[non_exhaustive]
pub enum StorageDialect {
    /// PostgreSQL production storage.
    Postgres,
    /// Spin-managed SQLite development storage.
    SpinSqlite,
}

/// Immutable migration embedded in the published crate.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct EmbeddedMigration {
    version: &'static str,
    sql: &'static str,
}

impl EmbeddedMigration {
    /// Returns the stable migration version.
    #[must_use]
    pub const fn version(self) -> &'static str {
        self.version
    }

    /// Returns the complete transaction-wrapped SQL document.
    #[must_use]
    pub const fn sql(self) -> &'static str {
        self.sql
    }

    /// Returns the executable statements without transaction-control commands.
    ///
    /// Spin host SQL adapters already execute a bounded list on one connection
    /// inside their own transaction. This view lets those adapters consume the
    /// same authoritative migration without nesting `BEGIN`/`COMMIT` or trying
    /// to execute SQLite pragmas through a PostgreSQL connection.
    ///
    /// # Errors
    ///
    /// Returns [`MigrationParseError`] when the embedded SQL contains an
    /// unterminated quoted string or block comment.
    pub fn statements(self) -> Result<Vec<&'static str>, MigrationParseError> {
        split_migration_statements(self.sql)
    }

    /// Computes the exact SHA-256 checksum that adapters persist after commit.
    #[must_use]
    pub fn checksum(self) -> [u8; 32] {
        Sha256::digest(self.sql.as_bytes()).into()
    }

    /// Returns the lowercase checksum representation used by migration tools.
    #[must_use]
    pub fn checksum_hex(self) -> String {
        self.checksum()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }
}

/// Failure while splitting an embedded SQL migration into host statements.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum MigrationParseError {
    /// A single-quoted SQL string was not terminated.
    #[error("migration contains an unterminated quoted string")]
    UnterminatedQuotedString,
    /// A `/* ... */` SQL comment was not terminated.
    #[error("migration contains an unterminated block comment")]
    UnterminatedBlockComment,
}

/// Storage dialect was selected without enabling its matching crate feature.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum StorageConfigurationError {
    /// PostgreSQL was requested without `storage-postgres`.
    #[error("storage-postgres feature is not enabled")]
    PostgresFeatureDisabled,
    /// Spin SQLite was requested without `storage-spin-sqlite`.
    #[error("storage-spin-sqlite feature is not enabled")]
    SpinSqliteFeatureDisabled,
}

/// Applied migration metadata read from durable storage.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AppliedMigration {
    /// Stable migration version.
    pub version: String,
    /// Lowercase SHA-256 checksum persisted after commit.
    pub checksum: String,
}

/// Migration validation or execution failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum MigrationError<E: StdError + Send + Sync + 'static> {
    /// Storage backend operation failed.
    #[error("migration backend failed: {0}")]
    Backend(#[source] E),
    /// An applied migration is unknown to this binary.
    #[error("database contains unknown future migration {0}")]
    UnknownVersion(String),
    /// An applied migration checksum differs from the immutable source.
    #[error("checksum drift detected for migration {version}")]
    ChecksumDrift {
        /// Migration whose checksum changed.
        version: String,
    },
    /// Migration history has a missing earlier version.
    #[error("migration gap detected before {0}")]
    Gap(String),
    /// Migration history contains the same version more than once.
    #[error("duplicate applied migration {0}")]
    DuplicateVersion(String),
}

/// Database-specific migration operations.
///
/// Implementations hold an exclusive startup lock from [`Self::acquire_lock`]
/// through [`Self::release_lock`]. [`Self::apply`] must execute the migration
/// statements and insert its checksum in one transaction, recording the row
/// only after every statement succeeds.
pub trait MigrationBackend: Sync {
    /// Backend failure type.
    type Error: StdError + Send + Sync + 'static;

    /// Acquires the dialect-specific startup lock.
    fn acquire_lock(&self) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Loads applied migrations ordered by version.
    fn applied(&self) -> impl Future<Output = Result<Vec<AppliedMigration>, Self::Error>> + Send;

    /// Atomically applies one migration and records its immutable checksum.
    fn apply(
        &self,
        migration: EmbeddedMigration,
    ) -> impl Future<Output = Result<(), Self::Error>> + Send;

    /// Releases the startup lock.
    fn release_lock(&self) -> impl Future<Output = Result<(), Self::Error>> + Send;
}

/// Lock-protected ordered migration runner.
#[derive(Clone, Copy, Debug)]
pub struct MigrationRunner {
    migrations: &'static [EmbeddedMigration],
}

impl MigrationRunner {
    /// Creates a runner for one enabled storage dialect.
    ///
    /// # Errors
    ///
    /// Returns [`StorageConfigurationError`] when the dialect feature is not
    /// enabled.
    pub fn for_dialect(dialect: StorageDialect) -> Result<Self, StorageConfigurationError> {
        Ok(Self {
            migrations: migrations(dialect)?,
        })
    }

    /// Returns pending migrations after validating durable history.
    ///
    /// # Errors
    ///
    /// Rejects duplicate, unknown, drifted, or gapped migration histories.
    pub fn plan<E>(
        &self,
        applied: &[AppliedMigration],
    ) -> Result<Vec<EmbeddedMigration>, MigrationError<E>>
    where
        E: StdError + Send + Sync + 'static,
    {
        let known = self
            .migrations
            .iter()
            .map(|migration| (migration.version(), *migration))
            .collect::<BTreeMap<_, _>>();
        let mut seen = BTreeMap::new();
        for migration in applied {
            if seen.insert(migration.version.as_str(), ()).is_some() {
                return Err(MigrationError::DuplicateVersion(migration.version.clone()));
            }
            let Some(expected) = known.get(migration.version.as_str()) else {
                return Err(MigrationError::UnknownVersion(migration.version.clone()));
            };
            if migration.checksum != expected.checksum_hex() {
                return Err(MigrationError::ChecksumDrift {
                    version: migration.version.clone(),
                });
            }
        }

        for expected in self.migrations.iter().take(applied.len()) {
            if !seen.contains_key(expected.version()) {
                return Err(MigrationError::Gap(expected.version().to_owned()));
            }
        }
        Ok(self.migrations[applied.len()..].to_vec())
    }

    /// Applies every pending migration while holding the backend startup lock.
    ///
    /// # Errors
    ///
    /// Returns a validation error or the first backend failure. Lock release is
    /// attempted on every path.
    pub async fn run<B>(&self, backend: &B) -> Result<(), MigrationError<B::Error>>
    where
        B: MigrationBackend,
    {
        backend
            .acquire_lock()
            .await
            .map_err(MigrationError::Backend)?;
        let result = async {
            let applied = backend.applied().await.map_err(MigrationError::Backend)?;
            for migration in self.plan(&applied)? {
                backend
                    .apply(migration)
                    .await
                    .map_err(MigrationError::Backend)?;
            }
            Ok(())
        }
        .await;
        let release = backend
            .release_lock()
            .await
            .map_err(MigrationError::Backend);
        result.and(release)
    }
}

fn split_migration_statements(sql: &'static str) -> Result<Vec<&'static str>, MigrationParseError> {
    let bytes = sql.as_bytes();
    let mut statements = Vec::new();
    let mut start = 0_usize;
    let mut index = 0_usize;
    let mut quoted = false;
    let mut line_comment = false;
    let mut block_comment = false;

    while index < bytes.len() {
        if line_comment {
            if bytes[index] == b'\n' {
                line_comment = false;
            }
            index += 1;
            continue;
        }
        if block_comment {
            if bytes[index] == b'*' && bytes.get(index + 1) == Some(&b'/') {
                block_comment = false;
                index += 2;
            } else {
                index += 1;
            }
            continue;
        }
        if quoted {
            if bytes[index] == b'\'' {
                if bytes.get(index + 1) == Some(&b'\'') {
                    index += 2;
                    continue;
                }
                quoted = false;
            }
            index += 1;
            continue;
        }

        match (bytes[index], bytes.get(index + 1).copied()) {
            (b'\'', _) => {
                quoted = true;
                index += 1;
            }
            (b'-', Some(b'-')) => {
                line_comment = true;
                index += 2;
            }
            (b'/', Some(b'*')) => {
                block_comment = true;
                index += 2;
            }
            (b';', _) => {
                push_executable_statement(&mut statements, &sql[start..index]);
                start = index + 1;
                index += 1;
            }
            _ => index += 1,
        }
    }

    if quoted {
        return Err(MigrationParseError::UnterminatedQuotedString);
    }
    if block_comment {
        return Err(MigrationParseError::UnterminatedBlockComment);
    }
    push_executable_statement(&mut statements, &sql[start..]);
    Ok(statements)
}

fn push_executable_statement(statements: &mut Vec<&'static str>, statement: &'static str) {
    let statement = statement.trim();
    let executable = statement
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with("--"))
        .collect::<String>()
        .to_ascii_uppercase();
    if statement.is_empty()
        || executable.starts_with("BEGIN")
        || executable.starts_with("COMMIT")
        || executable.starts_with("PRAGMA")
    {
        return;
    }
    statements.push(statement);
}

/// PostgreSQL production schema version 0001.
#[cfg(feature = "storage-postgres")]
pub const POSTGRES_0001: EmbeddedMigration = EmbeddedMigration {
    version: "0001_wasi_auth",
    sql: include_str!("../migrations/postgres/0001_wasi_auth.sql"),
};

/// Spin SQLite development schema version 0001.
#[cfg(feature = "storage-spin-sqlite")]
pub const SPIN_SQLITE_0001: EmbeddedMigration = EmbeddedMigration {
    version: "0001_wasi_auth",
    sql: include_str!("../migrations/sqlite/0001_wasi_auth.sql"),
};

/// Returns ordered migrations for one enabled dialect.
///
/// # Errors
///
/// Returns [`StorageConfigurationError`] if the caller requests a dialect whose
/// crate feature was not enabled.
pub fn migrations(
    dialect: StorageDialect,
) -> Result<&'static [EmbeddedMigration], StorageConfigurationError> {
    match dialect {
        StorageDialect::Postgres => {
            #[cfg(feature = "storage-postgres")]
            {
                static MIGRATIONS: [EmbeddedMigration; 1] = [POSTGRES_0001];
                Ok(&MIGRATIONS)
            }
            #[cfg(not(feature = "storage-postgres"))]
            Err(StorageConfigurationError::PostgresFeatureDisabled)
        }
        StorageDialect::SpinSqlite => {
            #[cfg(feature = "storage-spin-sqlite")]
            {
                static MIGRATIONS: [EmbeddedMigration; 1] = [SPIN_SQLITE_0001];
                Ok(&MIGRATIONS)
            }
            #[cfg(not(feature = "storage-spin-sqlite"))]
            Err(StorageConfigurationError::SpinSqliteFeatureDisabled)
        }
    }
}

#[cfg(test)]
mod tests {
    #[cfg(all(feature = "storage-postgres", feature = "storage-spin-sqlite"))]
    use std::collections::{BTreeMap, BTreeSet};

    use super::*;

    #[derive(Debug, Error)]
    #[error("fixture backend failure")]
    struct FixtureError;

    #[test]
    #[cfg(all(feature = "storage-postgres", feature = "storage-spin-sqlite"))]
    fn postgres_and_sqlite_have_identical_table_and_column_contracts() {
        let postgres = table_columns(POSTGRES_0001.sql());
        let sqlite = table_columns(SPIN_SQLITE_0001.sql());

        assert_eq!(postgres, sqlite);
        assert!(postgres.contains_key("auth_users"));
        assert!(postgres.contains_key("auth_secret_records"));
        assert!(postgres.contains_key("auth_events"));
        assert!(postgres.contains_key("auth_projection_records"));
        assert!(postgres.contains_key("auth_mail_outbox"));
        assert!(postgres.contains_key("auth_relationship_outbox"));
        assert!(postgres.contains_key("auth_idempotency"));
        assert!(postgres.contains_key("auth_rate_limit_buckets"));
    }

    #[test]
    #[cfg(feature = "storage-postgres")]
    fn postgres_migration_is_transaction_wrapped_and_checksummed() {
        let sql = POSTGRES_0001.sql().trim();
        assert!(sql.starts_with("BEGIN;"));
        assert!(sql.ends_with("COMMIT;"));
        assert_eq!(POSTGRES_0001.checksum_hex().len(), 64);
    }

    #[test]
    #[cfg(feature = "storage-spin-sqlite")]
    fn sqlite_migration_is_immediate_transaction_wrapped_and_checksummed() {
        let sql = SPIN_SQLITE_0001.sql().trim();
        assert!(sql.starts_with("PRAGMA foreign_keys = ON;\n\nBEGIN IMMEDIATE;"));
        assert!(sql.ends_with("COMMIT;"));
        assert_eq!(SPIN_SQLITE_0001.checksum_hex().len(), 64);
    }

    #[test]
    #[cfg(all(feature = "storage-postgres", feature = "storage-spin-sqlite"))]
    fn host_statement_views_share_the_reference_application_contract() {
        for migration in [POSTGRES_0001, SPIN_SQLITE_0001] {
            let statements = migration.statements().expect("valid embedded SQL");
            assert!(statements.len() >= 40);
            assert!(
                statements
                    .iter()
                    .any(|statement| statement.contains("CREATE TABLE IF NOT EXISTS events"))
            );
            assert!(statements.iter().any(|statement| {
                statement.contains("CREATE TABLE IF NOT EXISTS auth_password_credentials")
            }));
            assert!(statements.iter().all(|statement| {
                let normalized = statement.trim_start().to_ascii_uppercase();
                !normalized.starts_with("BEGIN")
                    && !normalized.starts_with("COMMIT")
                    && !normalized.starts_with("PRAGMA")
            }));
        }
    }

    #[test]
    fn migration_splitter_rejects_unterminated_syntax() {
        assert_eq!(
            split_migration_statements("SELECT 'unterminated"),
            Err(MigrationParseError::UnterminatedQuotedString)
        );
        assert_eq!(
            split_migration_statements("SELECT 1; /* unterminated"),
            Err(MigrationParseError::UnterminatedBlockComment)
        );
    }

    #[test]
    fn disabled_storage_dialects_return_configuration_errors() {
        #[cfg(not(feature = "storage-postgres"))]
        assert_eq!(
            migrations(StorageDialect::Postgres),
            Err(StorageConfigurationError::PostgresFeatureDisabled)
        );
        #[cfg(not(feature = "storage-spin-sqlite"))]
        assert_eq!(
            migrations(StorageDialect::SpinSqlite),
            Err(StorageConfigurationError::SpinSqliteFeatureDisabled)
        );
    }

    #[test]
    #[cfg(feature = "storage-postgres")]
    fn migration_plan_rejects_checksum_drift_and_future_versions() {
        let runner = MigrationRunner::for_dialect(StorageDialect::Postgres)
            .expect("PostgreSQL feature enabled");
        let drift = runner.plan::<FixtureError>(&[AppliedMigration {
            version: POSTGRES_0001.version().to_owned(),
            checksum: "00".repeat(32),
        }]);
        assert!(matches!(drift, Err(MigrationError::ChecksumDrift { .. })));

        let future = runner.plan::<FixtureError>(&[AppliedMigration {
            version: "9999_future".to_owned(),
            checksum: "00".repeat(32),
        }]);
        assert!(matches!(future, Err(MigrationError::UnknownVersion(_))));
    }

    #[test]
    #[cfg(feature = "storage-postgres")]
    fn migration_plan_returns_only_unapplied_suffix() {
        let runner = MigrationRunner::for_dialect(StorageDialect::Postgres)
            .expect("PostgreSQL feature enabled");
        let pending = runner.plan::<FixtureError>(&[]).expect("empty database");
        assert_eq!(pending, vec![POSTGRES_0001]);
        let complete = runner
            .plan::<FixtureError>(&[AppliedMigration {
                version: POSTGRES_0001.version().to_owned(),
                checksum: POSTGRES_0001.checksum_hex(),
            }])
            .expect("matching history");
        assert!(complete.is_empty());
    }

    #[cfg(all(feature = "storage-postgres", feature = "storage-spin-sqlite"))]
    fn table_columns(sql: &str) -> BTreeMap<String, BTreeSet<String>> {
        const PREFIX: &str = "CREATE TABLE IF NOT EXISTS ";
        let mut remaining = sql;
        let mut tables = BTreeMap::new();
        while let Some(start) = remaining.find(PREFIX) {
            remaining = &remaining[start + PREFIX.len()..];
            let name_end = remaining
                .find(|character: char| character.is_ascii_whitespace() || character == '(')
                .expect("table declaration has a name");
            let name = remaining[..name_end].trim().to_owned();
            let open = remaining.find('(').expect("table declaration opens");
            let close = matching_parenthesis(remaining, open);
            let body = &remaining[open + 1..close];
            let columns = split_top_level(body)
                .into_iter()
                .filter_map(|definition| {
                    let definition = definition.trim();
                    let upper = definition.to_ascii_uppercase();
                    if upper.starts_with("PRIMARY KEY")
                        || upper.starts_with("UNIQUE")
                        || upper.starts_with("FOREIGN KEY")
                        || upper.starts_with("CHECK")
                        || upper.starts_with("CONSTRAINT")
                    {
                        None
                    } else {
                        definition
                            .split_ascii_whitespace()
                            .next()
                            .map(|column| column.trim_matches('"').to_owned())
                    }
                })
                .collect();
            assert!(tables.insert(name, columns).is_none(), "duplicate table");
            remaining = &remaining[close + 1..];
        }
        tables
    }

    #[cfg(all(feature = "storage-postgres", feature = "storage-spin-sqlite"))]
    fn matching_parenthesis(value: &str, open: usize) -> usize {
        let mut depth = 0_u32;
        let mut quoted = false;
        let mut previous = '\0';
        for (offset, character) in value[open..].char_indices() {
            if character == '\'' && previous != '\\' {
                quoted = !quoted;
            }
            if !quoted {
                match character {
                    '(' => depth += 1,
                    ')' => {
                        depth -= 1;
                        if depth == 0 {
                            return open + offset;
                        }
                    }
                    _ => {}
                }
            }
            previous = character;
        }
        panic!("unbalanced migration table declaration")
    }

    #[cfg(all(feature = "storage-postgres", feature = "storage-spin-sqlite"))]
    fn split_top_level(value: &str) -> Vec<&str> {
        let mut parts = Vec::new();
        let mut start = 0;
        let mut depth = 0_u32;
        let mut quoted = false;
        let mut previous = '\0';
        for (index, character) in value.char_indices() {
            if character == '\'' && previous != '\\' {
                quoted = !quoted;
            }
            if !quoted {
                match character {
                    '(' => depth += 1,
                    ')' => depth -= 1,
                    ',' if depth == 0 => {
                        parts.push(&value[start..index]);
                        start = index + 1;
                    }
                    _ => {}
                }
            }
            previous = character;
        }
        parts.push(&value[start..]);
        parts
    }
}
