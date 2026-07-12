//! Spin host PostgreSQL transport for the relational authentication kernel.

use spin_sdk::pg::{Connection, DbValue, ParameterValue};
use thiserror::Error;

use super::{PgRow, PgValue, PostgresTransport};

/// Spin host PostgreSQL transport using one atomic statement per command.
#[derive(Clone)]
pub struct SpinPostgresTransport {
    database_url: String,
}

impl std::fmt::Debug for SpinPostgresTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("SpinPostgresTransport")
            .field("database_url", &"[REDACTED]")
            .finish()
    }
}

impl SpinPostgresTransport {
    /// Creates a transport for a non-empty PostgreSQL connection string.
    ///
    /// # Errors
    ///
    /// Rejects an empty or control-character-containing value.
    pub fn new(database_url: impl Into<String>) -> Result<Self, SpinPostgresError> {
        let database_url = database_url.into();
        if database_url.is_empty()
            || database_url.len() > 4_096
            || database_url.chars().any(char::is_control)
        {
            return Err(SpinPostgresError::InvalidConfiguration);
        }
        Ok(Self { database_url })
    }
}

impl PostgresTransport for SpinPostgresTransport {
    type Error = SpinPostgresError;

    fn violates_constraint(error: &Self::Error, constraint: &str) -> bool {
        matches!(error, SpinPostgresError::Host(message) if message.contains(constraint))
    }

    async fn query(
        &self,
        sql: &'static str,
        parameters: Vec<PgValue>,
    ) -> Result<Vec<PgRow>, Self::Error> {
        let connection = Connection::open(&self.database_url)
            .await
            .map_err(|error| SpinPostgresError::Host(format!("{error:?}")))?;
        let mut result = connection
            .query(
                sql,
                parameters
                    .into_iter()
                    .map(spin_parameter)
                    .collect::<Vec<_>>(),
            )
            .await
            .map_err(|error| SpinPostgresError::Host(format!("{error:?}")))?;
        let columns = result
            .columns()
            .iter()
            .map(|column| column.name.clone())
            .collect::<Vec<_>>();
        let mut rows = Vec::new();
        while let Some(row) = result.rows().next().await {
            if row.len() != columns.len() {
                return Err(SpinPostgresError::InvalidRow);
            }
            rows.push(PgRow::new(
                columns.iter().cloned().zip(row.into_iter().map(spin_value)),
            ));
        }
        result
            .result()
            .await
            .map_err(|error| SpinPostgresError::Host(format!("{error:?}")))?;
        Ok(rows)
    }
}

fn spin_parameter(value: PgValue) -> ParameterValue {
    match value {
        PgValue::Null => ParameterValue::DbNull,
        PgValue::Bool(value) => ParameterValue::Boolean(value),
        PgValue::I64(value) => ParameterValue::Int64(value),
        PgValue::Text(value) => ParameterValue::Str(value),
        PgValue::Bytes(value) => ParameterValue::Binary(value),
        PgValue::Json(value) => ParameterValue::Jsonb(value.to_string().into_bytes()),
    }
}

fn spin_value(value: DbValue) -> PgValue {
    match value {
        DbValue::DbNull => PgValue::Null,
        DbValue::Boolean(value) => PgValue::Bool(value),
        DbValue::Int8(value) => PgValue::I64(i64::from(value)),
        DbValue::Int16(value) => PgValue::I64(i64::from(value)),
        DbValue::Int32(value) => PgValue::I64(i64::from(value)),
        DbValue::Int64(value) => PgValue::I64(value),
        DbValue::Str(value) => PgValue::Text(value),
        DbValue::Binary(value) | DbValue::Unsupported(value) => PgValue::Bytes(value),
        DbValue::Jsonb(value) => {
            serde_json::from_slice(&value).map_or_else(|_| PgValue::Bytes(value), PgValue::Json)
        }
        other => PgValue::Text(format!("{other:?}")),
    }
}

/// Spin host PostgreSQL transport failure.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
#[non_exhaustive]
pub enum SpinPostgresError {
    /// Connection string failed bounded validation.
    #[error("Spin PostgreSQL connection configuration is invalid")]
    InvalidConfiguration,
    /// Spin host PostgreSQL operation failed; parameters are never included.
    #[error("Spin PostgreSQL host operation failed: {0}")]
    Host(String),
    /// Host returned a row whose value count did not match its columns.
    #[error("Spin PostgreSQL host returned a malformed row")]
    InvalidRow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_output_redacts_database_url() {
        let transport =
            SpinPostgresTransport::new("postgres://user:secret@example/db").expect("valid URL");
        let debug = format!("{transport:?}");

        assert!(debug.contains("[REDACTED]"));
        assert!(!debug.contains("secret"));
    }
}
