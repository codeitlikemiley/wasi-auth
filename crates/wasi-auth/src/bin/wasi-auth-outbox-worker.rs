//! Native durable-outbox worker for mail and optional SpiceDB relationships.

use std::env;
use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{Request, Response};
use thiserror::Error;
use tokio::time::MissedTickBehavior;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;
use wasi_auth::authentication::{Clock, RandomSource};
use wasi_auth::mail::{
    CaptureMailer, HttpMailBearerToken, HttpMailEndpoint, HttpMailTransport, HttpMailer, Mailer,
    ResendApiKey, ResendFromAddress, ResendMailer,
};
use wasi_auth::postgres::PostgresAuthStore;
use wasi_auth::postgres::native::{NativePostgresTransport, connection_requires_tls};
use wasi_auth::postgres::outbox::{MailOutboxWorker, PublicBaseUrl, RelationshipOutboxWorker};
use wasi_auth::postgres::workflows::OutboxSealingKey;
use wasi_auth::spicedb::{
    SpiceDbBearerToken, SpiceDbRelationshipWriter, SpiceDbTransport, SpiceDbWriteEndpoint,
};

const DEFAULT_POOL_SIZE: usize = 4;
const DEFAULT_MAIL_BATCH_SIZE: usize = 25;
const DEFAULT_RELATIONSHIP_BATCH_SIZE: usize = 100;
const DEFAULT_POLL_INTERVAL_MS: u64 = 500;
const MAX_HTTP_RESPONSE_BYTES: usize = 256 * 1024;
const MAX_MAIL_RESPONSE_BYTES: usize = 16 * 1024;
const DEVELOPMENT_OUTBOX_KEY: [u8; 32] = [
    220, 86, 219, 116, 4, 10, 30, 173, 152, 134, 172, 202, 41, 77, 70, 184, 0, 29, 70, 174, 231,
    102, 96, 212, 254, 37, 247, 102, 97, 151, 211, 106,
];

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .with_target(false)
        .init();

    if let Err(error) = run().await {
        error!(category = error.category(), "outbox worker failed to start");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), WorkerError> {
    let configuration = WorkerConfig::from_environment()?;
    let transport =
        NativePostgresTransport::connect_pool(&configuration.database_url, configuration.pool_size)
            .await
            .map_err(|_| WorkerError::DatabaseConnection)?;
    let store = PostgresAuthStore::new(transport);
    let http = NativeHttpTransport::new()?;
    let relationship_writer = configuration.spicedb.map(|configuration| {
        SpiceDbRelationshipWriter::new(configuration.endpoint, configuration.token, http.clone())
    });
    let sealing_key =
        OutboxSealingKey::new(configuration.outbox_key_version, configuration.outbox_key)
            .map_err(|_| WorkerError::InvalidOutboxKey)?;

    match configuration.mail {
        MailConfiguration::Capture => {
            run_worker_loop(
                store,
                CaptureMailer::default(),
                sealing_key,
                configuration.public_base_url,
                relationship_writer,
                configuration.mail_batch_size,
                configuration.relationship_batch_size,
                configuration.poll_interval,
            )
            .await
        }
        MailConfiguration::Http { endpoint, token } => {
            run_worker_loop(
                store,
                HttpMailer::new(endpoint, token, http),
                sealing_key,
                configuration.public_base_url,
                relationship_writer,
                configuration.mail_batch_size,
                configuration.relationship_batch_size,
                configuration.poll_interval,
            )
            .await
        }
        MailConfiguration::Resend { api_key, from } => {
            run_worker_loop(
                store,
                ResendMailer::new(api_key, from, http),
                sealing_key,
                configuration.public_base_url,
                relationship_writer,
                configuration.mail_batch_size,
                configuration.relationship_batch_size,
                configuration.poll_interval,
            )
            .await
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_worker_loop<M>(
    store: PostgresAuthStore<NativePostgresTransport>,
    mailer: M,
    sealing_key: OutboxSealingKey,
    public_base_url: PublicBaseUrl,
    relationship_writer: Option<SpiceDbRelationshipWriter<NativeHttpTransport>>,
    mail_batch_size: usize,
    relationship_batch_size: usize,
    poll_interval: Duration,
) -> Result<(), WorkerError>
where
    M: Mailer,
{
    let mail_worker = MailOutboxWorker::new(
        store.clone(),
        SystemClock,
        SystemRandom,
        sealing_key,
        public_base_url,
    );
    let relationship_worker = RelationshipOutboxWorker::new(store, SystemClock, SystemRandom);
    let mut ticker = tokio::time::interval(poll_interval);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    info!(
        mail_batch_size,
        relationship_batch_size,
        spicedb_enabled = relationship_writer.is_some(),
        "outbox worker started"
    );
    loop {
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|_| WorkerError::ShutdownSignal)?;
                info!("outbox worker stopped");
                return Ok(());
            }
            _ = ticker.tick() => {}
        }
        tokio::select! {
            signal = tokio::signal::ctrl_c() => {
                signal.map_err(|_| WorkerError::ShutdownSignal)?;
                info!("outbox worker stopped");
                return Ok(());
            }
            () = dispatch_pass(
                &mail_worker,
                &mailer,
                mail_batch_size,
                &relationship_worker,
                relationship_writer.as_ref(),
                relationship_batch_size,
            ) => {}
        }
    }
}

async fn dispatch_pass<M>(
    mail_worker: &MailOutboxWorker<NativePostgresTransport, SystemClock, SystemRandom>,
    mailer: &M,
    mail_batch_size: usize,
    relationship_worker: &RelationshipOutboxWorker<
        NativePostgresTransport,
        SystemClock,
        SystemRandom,
    >,
    relationship_writer: Option<&SpiceDbRelationshipWriter<NativeHttpTransport>>,
    relationship_batch_size: usize,
) where
    M: Mailer,
{
    match mail_worker.dispatch(mailer, mail_batch_size).await {
        Ok(report) if report.leased > 0 => info!(
            leased = report.leased,
            delivered = report.delivered,
            retried = report.retried,
            dead_lettered = report.dead_lettered,
            "mail outbox pass completed"
        ),
        Ok(_) => {}
        Err(_) => error!("mail outbox pass failed"),
    }
    if let Some(writer) = relationship_writer {
        match relationship_worker
            .dispatch(writer, relationship_batch_size)
            .await
        {
            Ok(report) if report.leased > 0 => info!(
                leased = report.leased,
                delivered = report.delivered,
                retried = report.retried,
                dead_lettered = report.dead_lettered,
                "relationship outbox pass completed"
            ),
            Ok(_) => {}
            Err(_) => error!("relationship outbox pass failed"),
        }
    }
}

#[derive(Clone)]
struct NativeHttpTransport {
    client: reqwest::Client,
}

impl NativeHttpTransport {
    fn new() -> Result<Self, WorkerError> {
        let client = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(5))
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .map_err(|_| WorkerError::HttpClient)?;
        Ok(Self { client })
    }

    async fn send_bounded(
        &self,
        request: Request<Vec<u8>>,
        maximum_response_bytes: usize,
    ) -> Result<Response<Vec<u8>>, NativeHttpError> {
        let (parts, body) = request.into_parts();
        let mut response = self
            .client
            .request(parts.method, parts.uri.to_string())
            .headers(parts.headers)
            .body(body)
            .send()
            .await
            .map_err(|_| NativeHttpError)?;
        if response
            .content_length()
            .is_some_and(|length| length > maximum_response_bytes as u64)
        {
            return Err(NativeHttpError);
        }
        let status = response.status();
        let headers = response.headers().clone();
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await.map_err(|_| NativeHttpError)? {
            if body.len().saturating_add(chunk.len()) > maximum_response_bytes {
                return Err(NativeHttpError);
            }
            body.extend_from_slice(&chunk);
        }
        let mut response = Response::new(body);
        *response.status_mut() = status;
        *response.headers_mut() = headers;
        Ok(response)
    }
}

impl HttpMailTransport for NativeHttpTransport {
    type Error = NativeHttpError;

    async fn send(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Self::Error> {
        self.send_bounded(request, MAX_MAIL_RESPONSE_BYTES).await
    }
}

impl SpiceDbTransport for NativeHttpTransport {
    type Error = NativeHttpError;

    async fn send(&self, request: Request<Vec<u8>>) -> Result<Response<Vec<u8>>, Self::Error> {
        self.send_bounded(request, MAX_HTTP_RESPONSE_BYTES).await
    }
}

#[derive(Clone, Copy, Debug, Error)]
#[error("native outbound HTTP request failed")]
struct NativeHttpError;

#[derive(Clone, Copy, Debug)]
struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

#[derive(Clone, Copy, Debug)]
struct SystemRandom;

impl RandomSource for SystemRandom {
    type Error = SystemRandomError;

    fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), Self::Error> {
        getrandom::fill(destination).map_err(|_| SystemRandomError)
    }
}

#[derive(Clone, Copy, Debug, Error)]
#[error("operating-system randomness is unavailable")]
struct SystemRandomError;

struct WorkerConfig {
    database_url: String,
    pool_size: usize,
    mail: MailConfiguration,
    public_base_url: PublicBaseUrl,
    outbox_key_version: String,
    outbox_key: [u8; 32],
    spicedb: Option<SpiceDbConfiguration>,
    mail_batch_size: usize,
    relationship_batch_size: usize,
    poll_interval: Duration,
}

enum MailConfiguration {
    Capture,
    Http {
        endpoint: HttpMailEndpoint,
        token: HttpMailBearerToken,
    },
    Resend {
        api_key: ResendApiKey,
        from: ResendFromAddress,
    },
}

struct SpiceDbConfiguration {
    endpoint: SpiceDbWriteEndpoint,
    token: SpiceDbBearerToken,
}

impl WorkerConfig {
    fn from_environment() -> Result<Self, WorkerError> {
        Self::from_values(|name| env::var(name).ok())
    }

    fn from_values(mut value: impl FnMut(&str) -> Option<String>) -> Result<Self, WorkerError> {
        let production = parse_bool(value("AUTH_PRODUCTION_MODE").as_deref(), false)?;
        let database_url = required(&mut value, "DATABASE_URL", 8_192)?;
        if production
            && !connection_requires_tls(&database_url).map_err(|_| WorkerError::DatabaseUrl)?
        {
            return Err(WorkerError::DatabaseTlsRequired);
        }
        let pool_size = bounded_usize(
            value("AUTH_OUTBOX_POSTGRES_POOL_SIZE").as_deref(),
            DEFAULT_POOL_SIZE,
            1,
            32,
        )?;
        let mail_batch_size = bounded_usize(
            value("AUTH_OUTBOX_MAIL_BATCH_SIZE").as_deref(),
            DEFAULT_MAIL_BATCH_SIZE,
            1,
            25,
        )?;
        let relationship_batch_size = bounded_usize(
            value("AUTH_OUTBOX_RELATIONSHIP_BATCH_SIZE").as_deref(),
            DEFAULT_RELATIONSHIP_BATCH_SIZE,
            1,
            100,
        )?;
        let poll_interval_ms = bounded_u64(
            value("AUTH_OUTBOX_POLL_INTERVAL_MS").as_deref(),
            DEFAULT_POLL_INTERVAL_MS,
            100,
            60_000,
        )?;
        let public_base_url_raw = required(&mut value, "AUTH_PUBLIC_BASE_URL", 2_048)?;
        if production && !public_base_url_raw.starts_with("https://") {
            return Err(WorkerError::PublicOrigin);
        }
        let public_base_url =
            PublicBaseUrl::new(&public_base_url_raw).map_err(|_| WorkerError::PublicOrigin)?;
        let outbox_key_version = required(&mut value, "AUTH_OUTBOX_KEY_VERSION", 128)?;
        if production && outbox_key_version == "development-v1" {
            return Err(WorkerError::InvalidOutboxKey);
        }
        let outbox_key = STANDARD
            .decode(required(&mut value, "AUTH_OUTBOX_KEY_BASE64", 256)?)
            .ok()
            .and_then(|bytes| bytes.try_into().ok())
            .ok_or(WorkerError::InvalidOutboxKey)?;
        if production && outbox_key == DEVELOPMENT_OUTBOX_KEY {
            return Err(WorkerError::InvalidOutboxKey);
        }

        let mail_transport = value("AUTH_MAIL_TRANSPORT")
            .unwrap_or_else(|| "capture".to_owned())
            .to_ascii_lowercase();
        let mail = match mail_transport.as_str() {
            "capture" if !production => MailConfiguration::Capture,
            "http" => {
                let endpoint = required(&mut value, "AUTH_MAIL_HTTP_URL", 2_048)?;
                if production && !endpoint.starts_with("https://") {
                    return Err(WorkerError::MailConfiguration);
                }
                MailConfiguration::Http {
                    endpoint: HttpMailEndpoint::new(&endpoint)
                        .map_err(|_| WorkerError::MailConfiguration)?,
                    token: HttpMailBearerToken::new(required(
                        &mut value,
                        "AUTH_MAIL_HTTP_TOKEN",
                        4_096,
                    )?)
                    .map_err(|_| WorkerError::MailConfiguration)?,
                }
            }
            "resend" => MailConfiguration::Resend {
                api_key: ResendApiKey::new(required(&mut value, "AUTH_RESEND_API_KEY", 4_096)?)
                    .map_err(|_| WorkerError::MailConfiguration)?,
                from: ResendFromAddress::new(required(&mut value, "AUTH_RESEND_FROM", 320)?)
                    .map_err(|_| WorkerError::MailConfiguration)?,
            },
            _ => return Err(WorkerError::MailConfiguration),
        };

        let spicedb = if parse_bool(value("AUTH_SPICEDB_ENABLED").as_deref(), false)? {
            let endpoint = required(&mut value, "AUTH_SPICEDB_WRITE_URL", 2_048)?;
            if production && !endpoint.starts_with("https://") {
                return Err(WorkerError::SpiceDbConfiguration);
            }
            Some(SpiceDbConfiguration {
                endpoint: SpiceDbWriteEndpoint::new(&endpoint)
                    .map_err(|_| WorkerError::SpiceDbConfiguration)?,
                token: SpiceDbBearerToken::new(required(&mut value, "AUTH_SPICEDB_TOKEN", 4_096)?)
                    .map_err(|_| WorkerError::SpiceDbConfiguration)?,
            })
        } else {
            None
        };

        Ok(Self {
            database_url,
            pool_size,
            mail,
            public_base_url,
            outbox_key_version,
            outbox_key,
            spicedb,
            mail_batch_size,
            relationship_batch_size,
            poll_interval: Duration::from_millis(poll_interval_ms),
        })
    }
}

fn required(
    value: &mut impl FnMut(&str) -> Option<String>,
    name: &'static str,
    maximum_length: usize,
) -> Result<String, WorkerError> {
    value(name)
        .filter(|candidate| {
            !candidate.is_empty()
                && candidate.len() <= maximum_length
                && !candidate.chars().any(char::is_control)
        })
        .ok_or(WorkerError::MissingOrInvalid(name))
}

fn parse_bool(value: Option<&str>, default: bool) -> Result<bool, WorkerError> {
    match value {
        None => Ok(default),
        Some("true" | "1") => Ok(true),
        Some("false" | "0") => Ok(false),
        Some(_) => Err(WorkerError::Boolean),
    }
}

fn bounded_usize(
    value: Option<&str>,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, WorkerError> {
    let parsed = value
        .map_or(Ok(default), str::parse::<usize>)
        .map_err(|_| WorkerError::Number)?;
    if (minimum..=maximum).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(WorkerError::Number)
    }
}

fn bounded_u64(
    value: Option<&str>,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, WorkerError> {
    let parsed = value
        .map_or(Ok(default), str::parse::<u64>)
        .map_err(|_| WorkerError::Number)?;
    if (minimum..=maximum).contains(&parsed) {
        Ok(parsed)
    } else {
        Err(WorkerError::Number)
    }
}

#[derive(Debug, Error)]
enum WorkerError {
    #[error("a required worker setting is missing or invalid")]
    MissingOrInvalid(&'static str),
    #[error("a worker boolean setting is invalid")]
    Boolean,
    #[error("a bounded worker number is invalid")]
    Number,
    #[error("the PostgreSQL URL is invalid")]
    DatabaseUrl,
    #[error("production PostgreSQL must require TLS")]
    DatabaseTlsRequired,
    #[error("PostgreSQL connection failed")]
    DatabaseConnection,
    #[error("the public application origin is invalid")]
    PublicOrigin,
    #[error("the outbox key is invalid")]
    InvalidOutboxKey,
    #[error("mail worker configuration is invalid")]
    MailConfiguration,
    #[error("SpiceDB worker configuration is invalid")]
    SpiceDbConfiguration,
    #[error("native HTTP client initialization failed")]
    HttpClient,
    #[error("shutdown signal handling failed")]
    ShutdownSignal,
}

impl WorkerError {
    const fn category(&self) -> &'static str {
        match self {
            Self::MissingOrInvalid(_) => "configuration",
            Self::Boolean | Self::Number => "configuration",
            Self::DatabaseUrl | Self::DatabaseTlsRequired => "database_configuration",
            Self::DatabaseConnection => "database_connection",
            Self::PublicOrigin => "public_origin",
            Self::InvalidOutboxKey => "outbox_key",
            Self::MailConfiguration => "mail_configuration",
            Self::SpiceDbConfiguration => "spicedb_configuration",
            Self::HttpClient => "http_client",
            Self::ShutdownSignal => "shutdown_signal",
        }
    }
}

impl fmt::Debug for WorkerConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WorkerConfig")
            .field("database_url", &"[REDACTED]")
            .field("pool_size", &self.pool_size)
            .field("mail", &"[REDACTED]")
            .field("public_base_url", &"[REDACTED]")
            .field("outbox_key_version", &self.outbox_key_version)
            .field("outbox_key", &"[REDACTED]")
            .field("spicedb", &self.spicedb.as_ref().map(|_| "[REDACTED]"))
            .field("mail_batch_size", &self.mail_batch_size)
            .field("relationship_batch_size", &self.relationship_batch_size)
            .field("poll_interval", &self.poll_interval)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn valid_values() -> BTreeMap<&'static str, String> {
        BTreeMap::from([
            (
                "DATABASE_URL",
                "postgres://user:secret@localhost/auth?sslmode=disable".to_owned(),
            ),
            ("AUTH_PUBLIC_BASE_URL", "http://127.0.0.1:3008".to_owned()),
            ("AUTH_OUTBOX_KEY_VERSION", "development-v1".to_owned()),
            ("AUTH_OUTBOX_KEY_BASE64", STANDARD.encode([7_u8; 32])),
            ("AUTH_MAIL_TRANSPORT", "capture".to_owned()),
        ])
    }

    fn configuration(values: &BTreeMap<&'static str, String>) -> Result<WorkerConfig, WorkerError> {
        WorkerConfig::from_values(|name| values.get(name).cloned())
    }

    #[test]
    fn development_capture_configuration_is_bounded() {
        let config = configuration(&valid_values()).expect("valid development config");

        assert!(matches!(config.mail, MailConfiguration::Capture));
        assert_eq!(config.mail_batch_size, 25);
        assert_eq!(config.relationship_batch_size, 100);
        assert!(config.spicedb.is_none());
        let debug = format!("{config:?}");
        assert!(!debug.contains("secret"));
        assert!(!debug.contains(&STANDARD.encode([7_u8; 32])));
    }

    #[test]
    fn production_rejects_capture_and_non_tls_database() {
        let mut values = valid_values();
        values.insert("AUTH_PRODUCTION_MODE", "true".to_owned());

        assert!(matches!(
            configuration(&values),
            Err(WorkerError::DatabaseTlsRequired)
        ));

        values.insert(
            "DATABASE_URL",
            "postgres://user:secret@db.example/auth?sslmode=require".to_owned(),
        );
        values.insert("AUTH_PUBLIC_BASE_URL", "https://app.example".to_owned());
        values.insert("AUTH_OUTBOX_KEY_BASE64", STANDARD.encode([8_u8; 32]));
        values.insert("AUTH_OUTBOX_KEY_VERSION", "production-v1".to_owned());
        assert!(matches!(
            configuration(&values),
            Err(WorkerError::MailConfiguration)
        ));

        values.insert("AUTH_MAIL_TRANSPORT", "http".to_owned());
        values.insert(
            "AUTH_MAIL_HTTP_URL",
            "https://mail.example.test/v1/deliver".to_owned(),
        );
        values.insert("AUTH_MAIL_HTTP_TOKEN", "mail-secret".to_owned());
        values.insert(
            "AUTH_OUTBOX_KEY_BASE64",
            STANDARD.encode(DEVELOPMENT_OUTBOX_KEY),
        );
        assert!(matches!(
            configuration(&values),
            Err(WorkerError::InvalidOutboxKey)
        ));
    }

    #[test]
    fn resend_configuration_requires_key_and_sender() {
        let mut values = valid_values();
        values.insert("AUTH_MAIL_TRANSPORT", "resend".to_owned());
        assert!(matches!(
            configuration(&values),
            Err(WorkerError::MissingOrInvalid("AUTH_RESEND_API_KEY"))
        ));

        values.insert("AUTH_RESEND_API_KEY", "re_test_key".to_owned());
        values.insert(
            "AUTH_RESEND_FROM",
            "Workspace <auth@example.test>".to_owned(),
        );
        assert!(matches!(
            configuration(&values).expect("valid Resend config").mail,
            MailConfiguration::Resend { .. }
        ));
    }

    #[test]
    fn partial_spicedb_configuration_fails_closed() {
        let mut values = valid_values();
        values.insert("AUTH_SPICEDB_ENABLED", "true".to_owned());
        values.insert(
            "AUTH_SPICEDB_WRITE_URL",
            "http://127.0.0.1:50051/v1/relationships/write".to_owned(),
        );

        assert!(matches!(
            configuration(&values),
            Err(WorkerError::MissingOrInvalid("AUTH_SPICEDB_TOKEN"))
        ));
    }

    #[test]
    fn batches_and_poll_interval_are_strictly_bounded() {
        let mut values = valid_values();
        values.insert("AUTH_OUTBOX_MAIL_BATCH_SIZE", "26".to_owned());
        assert!(matches!(configuration(&values), Err(WorkerError::Number)));

        values.insert("AUTH_OUTBOX_MAIL_BATCH_SIZE", "25".to_owned());
        values.insert("AUTH_OUTBOX_POLL_INTERVAL_MS", "99".to_owned());
        assert!(matches!(configuration(&values), Err(WorkerError::Number)));
    }
}
