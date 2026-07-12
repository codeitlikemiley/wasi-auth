//! Native Tokio PostgreSQL transport for workers, migrations, and tests.

use std::sync::Arc;

use thiserror::Error;
use tokio_postgres::types::{FromSqlOwned, Json, ToSql, Type};
use tokio_postgres::{Client, NoTls};

use super::{PgRow, PgValue, PostgresTransport};

/// Native pooled-client-compatible PostgreSQL query transport.
#[derive(Clone)]
pub struct NativePostgresTransport {
    client: Arc<Client>,
}

impl std::fmt::Debug for NativePostgresTransport {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativePostgresTransport")
            .finish_non_exhaustive()
    }
}

impl NativePostgresTransport {
    /// Wraps an established Tokio PostgreSQL client.
    #[must_use]
    pub fn from_client(client: Client) -> Self {
        Self {
            client: Arc::new(client),
        }
    }

    /// Opens a native PostgreSQL connection and drives it on the current Tokio
    /// runtime.
    ///
    /// # Errors
    ///
    /// Returns a connection error when PostgreSQL cannot be reached or TLS-free
    /// development/test negotiation fails.
    pub async fn connect(connection_string: &str) -> Result<Self, NativePostgresError> {
        let (client, connection) = tokio_postgres::connect(connection_string, NoTls)
            .await
            .map_err(NativePostgresError::Postgres)?;
        tokio::spawn(async move {
            let _ = connection.await;
        });
        Ok(Self::from_client(client))
    }

    /// Returns the underlying Tokio PostgreSQL client.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }
}

impl PostgresTransport for NativePostgresTransport {
    type Error = NativePostgresError;

    fn violates_constraint(error: &Self::Error, constraint: &str) -> bool {
        matches!(
            error,
            NativePostgresError::Postgres(error)
                if error.as_db_error().and_then(|error| error.constraint()) == Some(constraint)
        )
    }

    async fn query(
        &self,
        sql: &'static str,
        parameters: Vec<PgValue>,
    ) -> Result<Vec<PgRow>, Self::Error> {
        let parameters = parameters
            .into_iter()
            .map(native_parameter)
            .collect::<Vec<_>>();
        let references = parameters
            .iter()
            .map(|parameter| parameter.as_ref() as &(dyn ToSql + Sync))
            .collect::<Vec<_>>();
        self.client
            .query(sql, &references)
            .await
            .map_err(NativePostgresError::Postgres)?
            .into_iter()
            .map(decode_row)
            .collect()
    }
}

fn native_parameter(value: PgValue) -> Box<dyn ToSql + Sync + Send> {
    match value {
        PgValue::Null => Box::new(Option::<String>::None),
        PgValue::Bool(value) => Box::new(value),
        PgValue::I64(value) => Box::new(value),
        PgValue::Text(value) => Box::new(value),
        PgValue::Bytes(value) => Box::new(value),
        PgValue::Json(value) => Box::new(Json(value)),
    }
}

fn decode_row(row: tokio_postgres::Row) -> Result<PgRow, NativePostgresError> {
    let values = row
        .columns()
        .iter()
        .enumerate()
        .map(|(index, column)| {
            decode_value(&row, index, column.type_()).map(|value| (column.name().to_owned(), value))
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(PgRow::new(values))
}

fn decode_value(
    row: &tokio_postgres::Row,
    index: usize,
    data_type: &Type,
) -> Result<PgValue, NativePostgresError> {
    match *data_type {
        Type::BOOL => optional(row, index, PgValue::Bool),
        Type::INT2 => optional(row, index, |value: i16| PgValue::I64(i64::from(value))),
        Type::INT4 => optional(row, index, |value: i32| PgValue::I64(i64::from(value))),
        Type::INT8 => optional(row, index, PgValue::I64),
        Type::BYTEA => optional(row, index, PgValue::Bytes),
        Type::JSON | Type::JSONB => optional(row, index, |value: Json<serde_json::Value>| {
            PgValue::Json(value.0)
        }),
        Type::TEXT | Type::VARCHAR | Type::BPCHAR | Type::NAME => {
            optional(row, index, PgValue::Text)
        }
        _ => Err(NativePostgresError::UnsupportedType(
            data_type.name().to_owned(),
        )),
    }
}

fn optional<T>(
    row: &tokio_postgres::Row,
    index: usize,
    convert: impl FnOnce(T) -> PgValue,
) -> Result<PgValue, NativePostgresError>
where
    T: FromSqlOwned,
{
    row.try_get::<_, Option<T>>(index)
        .map(|value| value.map_or(PgValue::Null, convert))
        .map_err(NativePostgresError::Postgres)
}

/// Native PostgreSQL transport failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NativePostgresError {
    /// Tokio PostgreSQL operation failed.
    #[error("native PostgreSQL operation failed: {0}")]
    Postgres(#[source] tokio_postgres::Error),
    /// Query returned a column type outside the bounded auth wire contract.
    #[error("unsupported PostgreSQL result type {0}")]
    UnsupportedType(String),
}
