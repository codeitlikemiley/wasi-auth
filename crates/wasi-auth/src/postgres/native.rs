//! Native Tokio PostgreSQL transport for workers, migrations, and tests.

use std::{
    collections::HashMap,
    future::poll_fn,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
};

use thiserror::Error;
use tokio::sync::RwLock;
use tokio_postgres::config::SslMode;
use tokio_postgres::types::{FromSqlOwned, Json, ToSql, Type};
use tokio_postgres::{AsyncMessage, Client, Statement};
use tokio_postgres_rustls::MakeRustlsConnect;

use super::{PgRow, PgValue, PostgresTransport};

/// Native pooled-client-compatible PostgreSQL query transport.
#[derive(Clone)]
pub struct NativePostgresTransport {
    clients: Arc<Vec<NativeClient>>,
    next_client: Arc<AtomicUsize>,
}

struct NativeClient {
    client: Client,
    statements: RwLock<HashMap<&'static str, Statement>>,
}

const MAX_NATIVE_POOL_SIZE: usize = 128;
const MAX_STATEMENTS_PER_CONNECTION: usize = 128;
const AUTHORIZATION_INVALIDATION_CHANNEL: &str = "wasi_auth_context_invalidation";
static NEXT_INVALIDATION_TRACKER_ID: AtomicU64 = AtomicU64::new(1);

/// Process-local generation proving that PostgreSQL has not announced an
/// authorization-affecting commit since a snapshot was loaded.
///
/// Values can only be created by [`PostgresInvalidationTracker`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthorizationInvalidationEpoch {
    tracker_id: u64,
    generation: u64,
}

/// Healthy PostgreSQL `LISTEN/NOTIFY` subscription for authorization cache
/// invalidation.
///
/// Migration `0009_context_invalidation` emits one transactional notification
/// after any statement that can change an authenticated request context.
#[derive(Clone)]
pub struct PostgresInvalidationTracker {
    client: Arc<Client>,
    tracker_id: u64,
    generation: Arc<AtomicU64>,
    healthy: Arc<AtomicBool>,
}

impl std::fmt::Debug for PostgresInvalidationTracker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PostgresInvalidationTracker")
            .field("tracker_id", &self.tracker_id)
            .field("generation", &self.generation.load(Ordering::Acquire))
            .field("healthy", &self.healthy.load(Ordering::Acquire))
            .finish_non_exhaustive()
    }
}

impl PostgresInvalidationTracker {
    /// Opens a dedicated PostgreSQL notification connection and starts its
    /// driver on the current Tokio runtime.
    ///
    /// # Errors
    ///
    /// Returns a connection or `LISTEN` registration failure.
    pub async fn connect(connection_string: &str) -> Result<Self, NativePostgresError> {
        let (client, mut connection) =
            tokio_postgres::connect(connection_string, rustls_connector()?)
                .await
                .map_err(NativePostgresError::Postgres)?;
        let client = Arc::new(client);
        let generation = Arc::new(AtomicU64::new(1));
        let healthy = Arc::new(AtomicBool::new(false));
        let task_generation = Arc::clone(&generation);
        let task_healthy = Arc::clone(&healthy);
        tokio::spawn(async move {
            loop {
                match poll_fn(|context| connection.poll_message(context)).await {
                    Some(Ok(AsyncMessage::Notification(notification)))
                        if notification.channel() == AUTHORIZATION_INVALIDATION_CHANNEL =>
                    {
                        task_generation.fetch_add(1, Ordering::AcqRel);
                    }
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => {
                        task_healthy.store(false, Ordering::Release);
                        task_generation.fetch_add(1, Ordering::AcqRel);
                        break;
                    }
                }
            }
        });
        client
            .batch_execute(&format!("LISTEN {AUTHORIZATION_INVALIDATION_CHANNEL}"))
            .await
            .map_err(NativePostgresError::Postgres)?;
        let trigger_count: i64 = client
            .query_one(
                "SELECT COUNT(*)::BIGINT \
                 FROM (VALUES \
                    ('auth_users_context_invalidation', 'auth_users'), \
                    ('auth_sessions_context_invalidation', 'auth_sessions'), \
                    ('auth_organizations_context_invalidation', 'auth_organizations'), \
                    ('auth_memberships_context_invalidation', 'auth_memberships'), \
                    ('auth_role_permissions_context_invalidation', 'auth_role_permissions'), \
                    ('auth_policy_bundles_context_invalidation', 'auth_policy_bundles'), \
                    ('auth_system_administrators_context_invalidation', 'auth_system_administrators'), \
                    ('auth_signing_keys_context_invalidation', 'auth_signing_keys') \
                 ) AS expected(trigger_name, table_name) \
                 JOIN pg_trigger trigger ON trigger.tgname = expected.trigger_name \
                 JOIN pg_class relation ON relation.oid = trigger.tgrelid \
                                       AND relation.relname = expected.table_name \
                 JOIN pg_namespace namespace ON namespace.oid = relation.relnamespace \
                                            AND namespace.nspname = current_schema() \
                 WHERE NOT trigger.tgisinternal",
                &[],
            )
            .await
            .map_err(NativePostgresError::Postgres)?
            .get(0);
        if trigger_count != 8 {
            return Err(NativePostgresError::InvalidationSchemaUnavailable);
        }
        healthy.store(true, Ordering::Release);
        Ok(Self {
            client,
            tracker_id: NEXT_INVALIDATION_TRACKER_ID.fetch_add(1, Ordering::Relaxed),
            generation,
            healthy,
        })
    }

    /// Returns the current generation only while the notification connection
    /// is healthy. Callers must fall back to an authoritative query otherwise.
    ///
    /// # Errors
    ///
    /// Returns [`NativePostgresError::InvalidationListenerUnavailable`] after
    /// the listener disconnects.
    pub fn current_epoch(&self) -> Result<AuthorizationInvalidationEpoch, NativePostgresError> {
        if !self.healthy.load(Ordering::Acquire) {
            return Err(NativePostgresError::InvalidationListenerUnavailable);
        }
        Ok(AuthorizationInvalidationEpoch {
            tracker_id: self.tracker_id,
            generation: self.generation.load(Ordering::Acquire),
        })
    }

    /// Invalidates all process-local snapshots before forwarding a mutation
    /// that may alter authorization state. The transactional database
    /// notification provides the matching post-commit invalidation.
    pub fn invalidate(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
    }

    /// Returns the dedicated listener client for health probes.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.client
    }
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
            clients: Arc::new(vec![NativeClient {
                client,
                statements: RwLock::new(HashMap::new()),
            }]),
            next_client: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Opens a native PostgreSQL connection and drives it on the current Tokio
    /// runtime.
    ///
    /// # Errors
    ///
    /// Returns a connection error when PostgreSQL cannot be reached or rustls
    /// negotiation fails. `sslmode=disable` remains available for loopback
    /// development databases only.
    pub async fn connect(connection_string: &str) -> Result<Self, NativePostgresError> {
        Self::connect_pool(connection_string, 1).await
    }

    /// Opens a bounded native PostgreSQL connection pool. Statements are
    /// prepared once per physical connection and reused across requests.
    ///
    /// # Errors
    ///
    /// Returns a connection error or rejects pool sizes outside `1..=128`.
    pub async fn connect_pool(
        connection_string: &str,
        pool_size: usize,
    ) -> Result<Self, NativePostgresError> {
        if !(1..=MAX_NATIVE_POOL_SIZE).contains(&pool_size) {
            return Err(NativePostgresError::InvalidPoolSize);
        }
        let tls = rustls_connector()?;
        let mut clients = Vec::with_capacity(pool_size);
        for _ in 0..pool_size {
            let (client, connection) = tokio_postgres::connect(connection_string, tls.clone())
                .await
                .map_err(NativePostgresError::Postgres)?;
            tokio::spawn(async move {
                let _ = connection.await;
            });
            clients.push(NativeClient {
                client,
                statements: RwLock::new(HashMap::new()),
            });
        }
        Ok(Self {
            clients: Arc::new(clients),
            next_client: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Returns the underlying Tokio PostgreSQL client.
    #[must_use]
    pub fn client(&self) -> &Client {
        &self.clients[0].client
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
        let index = self.next_client.fetch_add(1, Ordering::Relaxed) % self.clients.len();
        let client = &self.clients[index];
        let statement = if let Some(statement) = client.statements.read().await.get(sql).cloned() {
            statement
        } else {
            let statement = client
                .client
                .prepare(sql)
                .await
                .map_err(NativePostgresError::Postgres)?;
            let mut statements = client.statements.write().await;
            if statements.len() >= MAX_STATEMENTS_PER_CONNECTION {
                statements.clear();
            }
            statements.insert(sql, statement.clone());
            statement
        };
        client
            .client
            .query(&statement, &references)
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

/// Returns whether a PostgreSQL connection string requires authenticated TLS.
///
/// Production callers should reject every other mode before opening a pool.
///
/// # Errors
///
/// Rejects malformed PostgreSQL connection configuration.
pub fn connection_requires_tls(connection_string: &str) -> Result<bool, NativePostgresError> {
    connection_string
        .parse::<tokio_postgres::Config>()
        .map(|config| config.get_ssl_mode() == SslMode::Require)
        .map_err(NativePostgresError::Postgres)
}

fn rustls_connector() -> Result<MakeRustlsConnect, NativePostgresError> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    if native.certs.is_empty() {
        return Err(NativePostgresError::InvalidTlsRoots);
    }
    for certificate in native.certs {
        roots
            .add(certificate)
            .map_err(|_| NativePostgresError::InvalidTlsRoots)?;
    }
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    Ok(MakeRustlsConnect::new(config))
}

/// Native PostgreSQL transport failure.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum NativePostgresError {
    /// The configured native pool was empty or unreasonably large.
    #[error("native PostgreSQL pool size must be between 1 and 128")]
    InvalidPoolSize,
    /// The notification connection is unavailable, so cache reuse is unsafe.
    #[error("PostgreSQL authorization invalidation listener is unavailable")]
    InvalidationListenerUnavailable,
    /// Migration 0009 is absent or incomplete, so notification-backed cache
    /// reuse cannot start safely.
    #[error("PostgreSQL authorization invalidation triggers are unavailable")]
    InvalidationSchemaUnavailable,
    /// Native/web PKI roots could not initialize a PostgreSQL TLS connector.
    #[error("PostgreSQL TLS root configuration is invalid")]
    InvalidTlsRoots,
    /// Tokio PostgreSQL operation failed.
    #[error("native PostgreSQL operation failed: {0}")]
    Postgres(#[source] tokio_postgres::Error),
    /// Query returned a column type outside the bounded auth wire contract.
    #[error("unsupported PostgreSQL result type {0}")]
    UnsupportedType(String),
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::*;

    #[test]
    #[ignore = "requires WASI_AUTH_TEST_POSTGRES_URL with migration 0009 applied"]
    fn transactional_notification_advances_authorization_epoch() {
        let database_url = std::env::var("WASI_AUTH_TEST_POSTGRES_URL")
            .expect("WASI_AUTH_TEST_POSTGRES_URL must be configured");
        tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .build()
            .expect("Tokio runtime")
            .block_on(async move {
                let tracker = PostgresInvalidationTracker::connect(&database_url)
                    .await
                    .expect("invalidation tracker");
                let before = tracker.current_epoch().expect("healthy tracker");
                tracker
                    .client()
                    .execute(
                        "UPDATE auth_users SET updated_at_ms = updated_at_ms WHERE FALSE",
                        &[],
                    )
                    .await
                    .expect("triggering statement");
                let deadline = Instant::now() + Duration::from_secs(1);
                while Instant::now() < deadline {
                    if tracker.current_epoch().expect("healthy tracker") != before {
                        return;
                    }
                    tokio::task::yield_now().await;
                }
                panic!("transactional invalidation was not observed within one second");
            });
    }
}
