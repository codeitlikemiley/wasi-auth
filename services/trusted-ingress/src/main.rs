//! Native trusted ingress for the production Spin deployment.

use std::{
    collections::VecDeque,
    convert::Infallible,
    env,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{SystemTime, UNIX_EPOCH},
};

use axum::{
    Json,
    body::{Body, to_bytes},
    extract::Request,
    response::{IntoResponse, Response},
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http::{HeaderValue, StatusCode, Uri, header::HOST, uri::Authority};
use hyper::service::service_fn;
use hyper_util::{
    client::legacy::{Client, connect::HttpConnector},
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder as ServerBuilder,
};
use serde::{Deserialize, Serialize};
use thiserror::Error;
use uuid::Uuid;
use wasi_auth::{
    authentication::Clock,
    authorization::{AccessRequest, ActionName, Resource, ResourceType},
    cedar::{
        CedarError, CedarProvider, DEFAULT_APPLICATION_POLICY, DEFAULT_APPLICATION_POLICY_REVISION,
        DEFAULT_APPLICATION_SCHEMA,
    },
    context::{
        AuthenticationAssurance, AuthorizationSnapshot, OrganizationId, PolicyRevision, Principal,
        RequestId, RoleId, SessionId, UserId, VerifiedRequestContext,
    },
    http::{
        AUTH_CONTEXT_HEADER, AuthenticatedSession, Credential, CredentialAuthenticator,
        DEFAULT_MAX_REQUEST_BODY_BYTES, HttpBoundaryError, REQUEST_ID_HEADER,
        ResponseSecurityPolicy, RoutePolicy, TrustedContextCodec, TrustedIngress,
        TrustedIngressConfig, apply_response_security, strip_untrusted_auth_metadata,
    },
    postgres::{
        PostgresAuthStore, PostgresStoreError,
        native::{
            AuthorizationInvalidationEpoch, NativePostgresError, NativePostgresTransport,
            PostgresInvalidationTracker, connection_requires_tls,
        },
        policy::{ActivePolicyBundle, PolicyBundleLoadError},
        tokens::{AccessTokenVerifier, JwtKeyRing, TokenServiceError, VerifiedAccessToken},
    },
};

const DEFAULT_TOKEN_CACHE_CAPACITY: usize = 4_096;

type NativeVerifier = AccessTokenVerifier<NativePostgresTransport, SystemClock>;
type ProxyClient = Client<HttpConnector, Body>;

#[derive(Clone)]
struct AppState {
    ingress: Arc<TrustedIngress<NativeAuthenticator, SystemClock>>,
    codec: Arc<TrustedContextCodec>,
    http1_client: ProxyClient,
    http2_client: ProxyClient,
    backend: Arc<BackendOrigin>,
    store: PostgresAuthStore<NativePostgresTransport>,
    invalidation_tracker: PostgresInvalidationTracker,
    cedar: Arc<tokio::sync::RwLock<CachedCedar>>,
    native_authorization_enabled: bool,
    secure_transport: bool,
}

struct BackendOrigin {
    authority: Authority,
    host: HeaderValue,
}

struct CachedCedar {
    provider: Arc<CedarProvider>,
    epoch: AuthorizationInvalidationEpoch,
}

#[derive(Clone)]
struct NativeAuthenticator {
    verifier: Arc<NativeVerifier>,
    store: PostgresAuthStore<NativePostgresTransport>,
    invalidation_tracker: PostgresInvalidationTracker,
    token_cache: Arc<Mutex<VecDeque<CachedToken>>>,
    token_cache_capacity: usize,
    cache_revalidate_ms: u64,
}

#[derive(Clone)]
struct CachedToken {
    key: [u8; 32],
    verified: VerifiedAccessToken,
    epoch: AuthorizationInvalidationEpoch,
    validated_at_ms: u64,
}

impl CredentialAuthenticator for NativeAuthenticator {
    type Error = NativeAuthenticationError;

    async fn authenticate(
        &self,
        credential: &Credential,
    ) -> Result<AuthenticatedSession, Self::Error> {
        match credential {
            Credential::Bearer(token) => {
                let epoch_before = self.invalidation_tracker.current_epoch().ok();
                if let (Some(cached), Some(current_epoch)) =
                    (self.cached_token(token), epoch_before)
                {
                    match self.verifier.verify_invalidation_cached(
                        token,
                        &cached.verified,
                        &cached.epoch,
                        &current_epoch,
                    ) {
                        Ok(Some(verified)) => return authenticated_session_from_token(verified),
                        Ok(None) => {}
                        Err(error) => {
                            self.remove_cached_token(token);
                            return Err(NativeAuthenticationError::Token(error));
                        }
                    }
                }
                let verified = self
                    .verifier
                    .verify(
                        token,
                        &RequestId::new(format!("ingress-{}", Uuid::now_v7()))
                            .map_err(|_| NativeAuthenticationError::InvalidContext)?,
                    )
                    .await
                    .map_err(NativeAuthenticationError::Token)?;
                let epoch_after = self.invalidation_tracker.current_epoch().ok();
                if let (Some(before), Some(after)) = (epoch_before, epoch_after)
                    && before == after
                {
                    self.cache_token(token, verified.clone(), after);
                }
                authenticated_session_from_token(verified)
            }
            Credential::SessionCookie(session_id) => {
                Uuid::parse_str(session_id)
                    .map_err(|_| NativeAuthenticationError::InvalidCredential)?;
                let session_id = SessionId::new(session_id.to_owned())
                    .map_err(|_| NativeAuthenticationError::InvalidCredential)?;
                let verified = self
                    .store
                    .load_verified_session(
                        &session_id,
                        RequestId::new(format!("ingress-{}", Uuid::now_v7()))
                            .map_err(|_| NativeAuthenticationError::InvalidContext)?,
                        SystemClock.now_unix_seconds(),
                    )
                    .await
                    .map_err(NativeAuthenticationError::Store)?;
                authenticated_session_from_context(verified.context())
            }
            _ => Err(NativeAuthenticationError::InvalidCredential),
        }
    }
}

impl NativeAuthenticator {
    fn cache_key(token: &str) -> [u8; 32] {
        use sha2::{Digest, Sha256};
        Sha256::digest(token.as_bytes()).into()
    }

    fn cached_token(&self, token: &str) -> Option<CachedToken> {
        let key = Self::cache_key(token);
        let mut cache = self.token_cache.lock().ok()?;
        let index = cache.iter().position(|candidate| candidate.key == key)?;
        let entry = cache.remove(index)?;
        if entry.verified.expires_at_seconds <= SystemClock.now_unix_seconds()
            || SystemClock
                .now_unix_millis()
                .saturating_sub(entry.validated_at_ms)
                > self.cache_revalidate_ms
        {
            return None;
        }
        let verified = entry.clone();
        cache.push_back(entry);
        Some(verified)
    }

    fn cache_token(
        &self,
        token: &str,
        verified: VerifiedAccessToken,
        epoch: AuthorizationInvalidationEpoch,
    ) {
        let key = Self::cache_key(token);
        let Ok(mut cache) = self.token_cache.lock() else {
            return;
        };
        if let Some(index) = cache.iter().position(|candidate| candidate.key == key) {
            cache.remove(index);
        }
        cache.push_back(CachedToken {
            key,
            verified,
            epoch,
            validated_at_ms: SystemClock.now_unix_millis(),
        });
        while cache.len() > self.token_cache_capacity {
            cache.pop_front();
        }
    }

    fn remove_cached_token(&self, token: &str) {
        let key = Self::cache_key(token);
        let Ok(mut cache) = self.token_cache.lock() else {
            return;
        };
        if let Some(index) = cache.iter().position(|candidate| candidate.key == key) {
            cache.remove(index);
        }
    }
}

#[derive(Clone, Copy, Debug)]
struct SystemClock;

impl Clock for SystemClock {
    fn now_unix_seconds(&self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs())
    }
}

impl SystemClock {
    fn now_unix_millis(self) -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_millis() as u64)
    }
}

#[derive(Debug, Error)]
enum NativeAuthenticationError {
    #[error("access-token authentication failed")]
    Token(#[source] TokenServiceError<NativePostgresError>),
    #[error("session authentication failed")]
    Store(#[source] PostgresStoreError<NativePostgresError>),
    #[error("credential is malformed or unsupported")]
    InvalidCredential,
    #[error("authenticated context is invalid")]
    InvalidContext,
}

impl NativeAuthenticationError {
    fn is_credential_rejection(&self) -> bool {
        match self {
            Self::Token(
                TokenServiceError::InvalidSession
                | TokenServiceError::InvalidToken
                | TokenServiceError::ExpiredToken
                | TokenServiceError::ReuseDetected,
            )
            | Self::Store(PostgresStoreError::Unauthenticated) => true,
            Self::InvalidCredential => true,
            Self::Token(_) | Self::Store(_) | Self::InvalidContext => false,
        }
    }
}

#[derive(Debug, Error)]
enum StartupError {
    #[error("{0} is required")]
    Missing(&'static str),
    #[error("{0} is invalid")]
    Invalid(&'static str),
    #[error("PostgreSQL initialization failed: {0}")]
    Postgres(#[from] NativePostgresError),
    #[error("Cedar initialization failed: {0}")]
    Cedar(#[from] CedarRuntimeError),
    #[error("listener initialization failed: {0}")]
    Listener(#[from] std::io::Error),
}

#[derive(Debug, Error)]
enum CedarRuntimeError {
    #[error(transparent)]
    Invalidation(#[from] NativePostgresError),
    #[error(transparent)]
    Load(#[from] PolicyBundleLoadError<NativePostgresError>),
    #[error(transparent)]
    Cedar(#[from] CedarError),
    #[error("active Cedar entities could not be serialized")]
    Serialization(#[from] serde_json::Error),
    #[error("active Cedar policy changed repeatedly while it was loading")]
    UnstableRevision,
}

#[tokio::main]
async fn main() -> Result<(), StartupError> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .init();
    let database_url = required("DATABASE_URL")?;
    let production = bool_env("AUTH_PRODUCTION_MODE", false)?;
    if production
        && !connection_requires_tls(&database_url)
            .map_err(|_| StartupError::Invalid("DATABASE_URL"))?
    {
        return Err(StartupError::Invalid(
            "DATABASE_URL must set sslmode=require in production",
        ));
    }
    let pool_size = usize_env("AUTH_INGRESS_POSTGRES_POOL_SIZE", 32, 1, 128)?;
    let cache_capacity = usize_env(
        "AUTH_INGRESS_TOKEN_CACHE_CAPACITY",
        DEFAULT_TOKEN_CACHE_CAPACITY,
        1,
        65_536,
    )?;
    let cache_revalidate_ms =
        usize_env("AUTH_INGRESS_CACHE_REVALIDATE_MS", 1_000, 50, 5_000)? as u64;
    let transport = NativePostgresTransport::connect_pool(&database_url, pool_size).await?;
    let invalidation_tracker = PostgresInvalidationTracker::connect(&database_url).await?;
    let store = PostgresAuthStore::new(transport);
    let (cedar, cedar_epoch) = load_consistent_cedar(&store, &invalidation_tracker).await?;
    let issuer = env::var("AUTH_JWT_ISSUER").unwrap_or_else(|_| "http://127.0.0.1:3008".to_owned());
    let audience = env::var("AUTH_JWT_AUDIENCE").unwrap_or_else(|_| "fullstack-app".to_owned());
    let verifier = AccessTokenVerifier::new(
        store.clone(),
        SystemClock,
        jwt_key_ring(production)?,
        issuer,
        audience,
    )
    .map_err(|_| StartupError::Invalid("JWT verification configuration"))?;
    let authenticator = NativeAuthenticator {
        verifier: Arc::new(verifier),
        store: store.clone(),
        invalidation_tracker: invalidation_tracker.clone(),
        token_cache: Arc::new(Mutex::new(VecDeque::new())),
        token_cache_capacity: cache_capacity,
        cache_revalidate_ms,
    };
    let public_origin =
        env::var("AUTH_PUBLIC_BASE_URL").unwrap_or_else(|_| "http://127.0.0.1:3008".to_owned());
    let mut ingress_config = TrustedIngressConfig::new(public_origin)
        .map_err(|_| StartupError::Invalid("AUTH_PUBLIC_BASE_URL"))?;
    if !production {
        ingress_config = ingress_config.with_development_session_cookie();
    }
    let key = ingress_key()?;
    let context_audience =
        env::var("AUTH_TRUSTED_INGRESS_AUDIENCE").unwrap_or_else(|_| "fullstack-app".to_owned());
    let context_max_age = usize_env("AUTH_TRUSTED_INGRESS_MAX_AGE_SECONDS", 5, 1, 30)? as u64;
    let codec = TrustedContextCodec::new(context_audience, key)
        .and_then(|codec| codec.with_max_age_seconds(context_max_age))
        .map_err(|_| StartupError::Invalid("AUTH_TRUSTED_INGRESS_KEY_BASE64"))?;
    let backend_origin = env::var("AUTH_INGRESS_BACKEND_ORIGIN")
        .unwrap_or_else(|_| "http://127.0.0.1:3009".to_owned());
    let backend = Arc::new(parse_backend_origin(&backend_origin, production)?);
    let listen = env::var("AUTH_INGRESS_LISTEN")
        .unwrap_or_else(|_| "127.0.0.1:3008".to_owned())
        .parse::<SocketAddr>()
        .map_err(|_| StartupError::Invalid("AUTH_INGRESS_LISTEN"))?;

    let mut connector = HttpConnector::new();
    connector.enforce_http(false);
    let http1_client = Client::builder(TokioExecutor::new()).build(connector.clone());
    let mut http2_builder = Client::builder(TokioExecutor::new());
    http2_builder.http2_only(true);
    let http2_client = http2_builder.build(connector);
    let state = AppState {
        ingress: Arc::new(TrustedIngress::new(
            ingress_config,
            authenticator,
            SystemClock,
        )),
        codec: Arc::new(codec),
        http1_client,
        http2_client,
        backend,
        store,
        invalidation_tracker,
        cedar: Arc::new(tokio::sync::RwLock::new(CachedCedar {
            provider: cedar,
            epoch: cedar_epoch,
        })),
        native_authorization_enabled: !bool_env("AUTH_SPICEDB_ENABLED", false)?,
        secure_transport: env::var("AUTH_PUBLIC_BASE_URL")
            .unwrap_or_else(|_| "http://127.0.0.1:3008".to_owned())
            .starts_with("https://"),
    };
    let listener = tokio::net::TcpListener::bind(listen).await?;
    tracing::info!(%listen, "native trusted ingress is ready");
    serve(listener, state).await.map_err(StartupError::Listener)
}

async fn serve(listener: tokio::net::TcpListener, state: AppState) -> Result<(), std::io::Error> {
    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            _ = &mut shutdown => return Ok(()),
            accepted = listener.accept() => {
                let (stream, peer) = accepted?;
                stream.set_nodelay(true)?;
                let state = state.clone();
                tokio::spawn(async move {
                    let service = service_fn(move |request: http::Request<hyper::body::Incoming>| {
                        let state = state.clone();
                        async move {
                            Ok::<_, Infallible>(proxy_request(state, request.map(Body::new)).await)
                        }
                    });
                    let builder = ServerBuilder::new(TokioExecutor::new());
                    if let Err(error) = builder
                        .serve_connection_with_upgrades(TokioIo::new(stream), service)
                        .await
                    {
                        tracing::debug!(%peer, error = %error, "trusted ingress connection closed");
                    }
                });
            }
        }
    }
}

async fn proxy_request(state: AppState, mut request: Request) -> Response {
    strip_untrusted_auth_metadata(request.headers_mut());
    if let Err(status) = ensure_request_id(&mut request) {
        return (status, "Request correlation is invalid.").into_response();
    }
    let context = if request.headers().contains_key(http::header::AUTHORIZATION)
        || request.headers().contains_key(http::header::COOKIE)
    {
        // Authenticate an owned metadata-only request so the streaming body is
        // never borrowed across an await and remains available for
        // backpressured HTTP/gRPC forwarding. Credential-free traffic skips
        // this allocation entirely; authenticated routes still fail closed in
        // the guest when no verified envelope is installed.
        let mut authentication_request = match http::Request::builder()
            .method(request.method().clone())
            .uri(request.uri().clone())
            .body(())
        {
            Ok(request) => request,
            Err(_) => return internal_error(),
        };
        *authentication_request.headers_mut() = request.headers().clone();
        match state
            .ingress
            .authenticate_request(&authentication_request, RoutePolicy::Optional)
            .await
        {
            Ok(context) => context,
            Err(error) => return boundary_error(error, &request),
        }
    } else {
        None
    };
    if state.native_authorization_enabled
        && request.headers().contains_key(http::header::AUTHORIZATION)
        && request.method() == http::Method::POST
        && matches!(
            request.uri().path(),
            "/api/authorization/check" | "/api/authorization/batch-check"
        )
    {
        return native_authorization_request(state, request, context).await;
    }
    if let Some(context) = context {
        let envelope = match state.codec.seal(
            &context,
            request.method(),
            request.uri().path(),
            SystemClock.now_unix_seconds(),
        ) {
            Ok(envelope) => envelope,
            Err(error) => {
                tracing::error!(error = %error, "failed to seal trusted request context");
                return internal_error();
            }
        };
        let header = match HeaderValue::from_str(&envelope) {
            Ok(header) => header,
            Err(_) => return internal_error(),
        };
        request.headers_mut().insert(AUTH_CONTEXT_HEADER, header);
    }
    if mutation_may_change_authorization(request.method(), request.uri().path()) {
        state.invalidation_tracker.invalidate();
    }
    let uri = match backend_uri(&state.backend, request.uri()) {
        Ok(uri) => uri,
        Err(_) => return internal_error(),
    };
    *request.uri_mut() = uri;
    let grpc = is_grpc_request(&request);
    if grpc {
        *request.version_mut() = http::Version::HTTP_2;
        remove_http2_hop_headers(request.headers_mut());
    } else {
        *request.version_mut() = http::Version::HTTP_11;
        request
            .headers_mut()
            .insert(HOST, state.backend.host.clone());
    }
    let response = if grpc {
        state.http2_client.request(request).await
    } else {
        state.http1_client.request(request).await
    };
    match response {
        Ok(response) => response.map(Body::new),
        Err(error) => {
            tracing::error!(error = %error, "trusted ingress backend request failed");
            internal_error()
        }
    }
}

fn is_grpc_request(request: &Request) -> bool {
    request
        .headers()
        .get(http::header::CONTENT_TYPE)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.starts_with("application/grpc"))
}

fn remove_http2_hop_headers(headers: &mut http::HeaderMap) {
    headers.remove(HOST);
    headers.remove(http::header::CONNECTION);
    headers.remove(http::header::TRANSFER_ENCODING);
    headers.remove(http::header::UPGRADE);
    headers.remove("keep-alive");
    headers.remove("proxy-connection");
}

#[derive(Clone, Debug, Deserialize)]
struct AuthorizationCheckInput {
    action: String,
    resource_type: String,
    resource_id: String,
    #[serde(default)]
    organization_id: Option<String>,
}

#[derive(Debug, Deserialize)]
struct AuthorizationBatchInput {
    checks: Vec<AuthorizationCheckInput>,
}

#[derive(Debug, Serialize)]
struct AuthorizationCheckOutput {
    allowed: bool,
    reason: String,
    policy_revision: String,
    consistency_token: Option<String>,
    resource_revision: Option<u64>,
}

#[derive(Debug, Serialize)]
struct AuthorizationBatchOutput {
    results: Vec<AuthorizationCheckOutput>,
}

async fn native_authorization_request(
    state: AppState,
    request: Request,
    context: Option<VerifiedRequestContext>,
) -> Response {
    let Some(context) = context else {
        return (StatusCode::UNAUTHORIZED, "Authentication is required.").into_response();
    };
    let path = request.uri().path().to_owned();
    let cedar = match current_cedar(&state).await {
        Ok(cedar) => cedar,
        Err(error) => {
            tracing::error!(error = %error, "active Cedar policy reload failed closed");
            return (
                StatusCode::SERVICE_UNAVAILABLE,
                "Authorization is unavailable.",
            )
                .into_response();
        }
    };
    let body = match to_bytes(request.into_body(), DEFAULT_MAX_REQUEST_BODY_BYTES).await {
        Ok(body) => body,
        Err(_) => {
            return (
                StatusCode::PAYLOAD_TOO_LARGE,
                "Authorization request is too large.",
            )
                .into_response();
        }
    };
    let response = if path == "/api/authorization/check" {
        let input = match serde_json::from_slice::<AuthorizationCheckInput>(&body) {
            Ok(input) => input,
            Err(_) => {
                return (StatusCode::BAD_REQUEST, "Authorization request is invalid.")
                    .into_response();
            }
        };
        match evaluate_authorization(&cedar, input, &context) {
            Ok(result) => Json(result).into_response(),
            Err(status) => (status, "Authorization request was rejected.").into_response(),
        }
    } else {
        let input = match serde_json::from_slice::<AuthorizationBatchInput>(&body) {
            Ok(input) if input.checks.len() <= 100 => input,
            _ => {
                return (StatusCode::BAD_REQUEST, "Authorization batch is invalid.")
                    .into_response();
            }
        };
        let results = input
            .checks
            .into_iter()
            .map(|check| evaluate_authorization(&cedar, check, &context))
            .collect::<Result<Vec<_>, _>>();
        match results {
            Ok(results) => Json(AuthorizationBatchOutput { results }).into_response(),
            Err(status) => (status, "Authorization request was rejected.").into_response(),
        }
    };
    secure_authorization_response(response, state.secure_transport)
}

async fn current_cedar(state: &AppState) -> Result<Arc<CedarProvider>, CedarRuntimeError> {
    let current_epoch = state.invalidation_tracker.current_epoch()?;
    {
        let cached = state.cedar.read().await;
        if cached.epoch == current_epoch {
            return Ok(Arc::clone(&cached.provider));
        }
    }

    let mut cached = state.cedar.write().await;
    let current_epoch = state.invalidation_tracker.current_epoch()?;
    if cached.epoch == current_epoch {
        return Ok(Arc::clone(&cached.provider));
    }
    let (provider, epoch) =
        load_consistent_cedar(&state.store, &state.invalidation_tracker).await?;
    cached.provider = Arc::clone(&provider);
    cached.epoch = epoch;
    Ok(provider)
}

async fn load_consistent_cedar(
    store: &PostgresAuthStore<NativePostgresTransport>,
    tracker: &PostgresInvalidationTracker,
) -> Result<(Arc<CedarProvider>, AuthorizationInvalidationEpoch), CedarRuntimeError> {
    for _ in 0..3 {
        let epoch_before = tracker.current_epoch()?;
        let provider = load_cedar(store).await?;
        let epoch_after = tracker.current_epoch()?;
        if epoch_before == epoch_after {
            return Ok((Arc::new(provider), epoch_after));
        }
    }
    Err(CedarRuntimeError::UnstableRevision)
}

async fn load_cedar(
    store: &PostgresAuthStore<NativePostgresTransport>,
) -> Result<CedarProvider, CedarRuntimeError> {
    match store.load_active_policy_bundle().await? {
        Some(bundle) => cedar_from_active_bundle(bundle),
        None => CedarProvider::new_validated(
            DEFAULT_APPLICATION_POLICY,
            DEFAULT_APPLICATION_SCHEMA,
            "[]",
            DEFAULT_APPLICATION_POLICY_REVISION,
        )
        .map_err(CedarRuntimeError::from),
    }
}

fn cedar_from_active_bundle(
    bundle: ActivePolicyBundle,
) -> Result<CedarProvider, CedarRuntimeError> {
    let entities = serde_json::to_string(&bundle.entities)?;
    CedarProvider::new_validated(
        &bundle.cedar_policy,
        &bundle.cedar_schema,
        &entities,
        bundle.policy_revision,
    )
    .map_err(CedarRuntimeError::from)
}

fn evaluate_authorization(
    cedar: &CedarProvider,
    input: AuthorizationCheckInput,
    context: &VerifiedRequestContext,
) -> Result<AuthorizationCheckOutput, StatusCode> {
    let requested_action = ActionName::new(input.action).map_err(|_| StatusCode::BAD_REQUEST)?;
    let requested_resource_type =
        ResourceType::new(input.resource_type).map_err(|_| StatusCode::BAD_REQUEST)?;
    let organization_id = input
        .organization_id
        .map(OrganizationId::new)
        .transpose()
        .map_err(|_| StatusCode::BAD_REQUEST)?
        .or_else(|| context.auth().organization_id().cloned());
    let resource = Resource::new(
        ResourceType::new("ApplicationResource").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        format!("{}:{}", requested_resource_type.as_str(), input.resource_id),
        organization_id,
    )
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    let mut permissions = context
        .authorization()
        .permissions()
        .map(str::to_owned)
        .collect::<Vec<_>>();
    if context.auth().principal().is_system_administrator()
        && context.auth().assurance() == AuthenticationAssurance::Aal2
    {
        permissions.push(requested_action.as_str().to_owned());
    }
    let authorization = AuthorizationSnapshot::new(permissions, [], None, None)
        .map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    let request = AccessRequest::new(
        context.auth().clone(),
        ActionName::new("authorization.check").map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?,
        resource,
    )
    .map_err(|_| StatusCode::FORBIDDEN)?
    .with_authorization_snapshot(authorization)
    .with_attribute("requested_action", requested_action.as_str())
    .and_then(|request| {
        request.with_attribute("requested_resource_type", requested_resource_type.as_str())
    })
    .map_err(|_| StatusCode::BAD_REQUEST)?;
    let decision = cedar
        .check_sync(&request)
        .map_err(|_| StatusCode::SERVICE_UNAVAILABLE)?;
    Ok(AuthorizationCheckOutput {
        allowed: decision.is_allowed(),
        reason: decision.reason().to_owned(),
        policy_revision: decision.policy_revision().to_string(),
        consistency_token: decision.consistency_token().map(str::to_owned),
        resource_revision: None,
    })
}

fn secure_authorization_response(mut response: Response, secure_transport: bool) -> Response {
    apply_response_security(
        &mut response,
        ResponseSecurityPolicy::Sensitive,
        secure_transport,
    );
    response
}

fn mutation_may_change_authorization(method: &http::Method, path: &str) -> bool {
    !matches!(
        *method,
        http::Method::GET | http::Method::HEAD | http::Method::OPTIONS
    ) && !path.starts_with("/api/authorization/")
        && !path.contains("authorization.v1.AuthorizationService/")
}

fn authenticated_session_from_token(
    verified: VerifiedAccessToken,
) -> Result<AuthenticatedSession, NativeAuthenticationError> {
    let policy_revision = verified
        .policy_revision
        .map(PolicyRevision::new)
        .transpose()
        .map_err(|_| NativeAuthenticationError::InvalidContext)?;
    Ok(AuthenticatedSession {
        principal: Principal::new(
            UserId::new(verified.user_id).map_err(|_| NativeAuthenticationError::InvalidContext)?,
            "wasi-auth",
            verified.system_administrator,
        )
        .map_err(|_| NativeAuthenticationError::InvalidContext)?,
        organization_id: verified
            .organization_id
            .map(OrganizationId::new)
            .transpose()
            .map_err(|_| NativeAuthenticationError::InvalidContext)?,
        session_id: SessionId::new(verified.session_id)
            .map_err(|_| NativeAuthenticationError::InvalidContext)?,
        assurance: match verified.assurance.as_str() {
            "aal1" => wasi_auth::context::AuthenticationAssurance::Aal1,
            "aal2" => wasi_auth::context::AuthenticationAssurance::Aal2,
            _ => return Err(NativeAuthenticationError::InvalidContext),
        },
        issued_at_unix_seconds: verified.issued_at_seconds,
        expires_at_unix_seconds: verified.expires_at_seconds,
        decision_id: None,
        policy_revision: policy_revision.clone(),
        authorization: AuthorizationSnapshot::new(
            verified.permissions,
            verified
                .role_ids
                .into_iter()
                .map(RoleId::new)
                .collect::<Result<Vec<_>, _>>()
                .map_err(|_| NativeAuthenticationError::InvalidContext)?,
            policy_revision,
            None,
        )
        .map_err(|_| NativeAuthenticationError::InvalidContext)?,
    })
}

fn authenticated_session_from_context(
    context: &VerifiedRequestContext,
) -> Result<AuthenticatedSession, NativeAuthenticationError> {
    Ok(AuthenticatedSession {
        principal: context.auth().principal().clone(),
        organization_id: context.auth().organization_id().cloned(),
        session_id: context.auth().session_id().clone(),
        assurance: context.auth().assurance(),
        issued_at_unix_seconds: context.auth().issued_at_unix_seconds(),
        expires_at_unix_seconds: context.auth().expires_at_unix_seconds(),
        decision_id: context.auth().decision_id().cloned(),
        policy_revision: context.auth().policy_revision().cloned(),
        authorization: context.authorization().clone(),
    })
}

fn boundary_error(
    error: HttpBoundaryError<NativeAuthenticationError>,
    request: &Request,
) -> Response {
    let credential_rejection = matches!(
        &error,
        HttpBoundaryError::Authenticator(error) if error.is_credential_rejection()
    );
    let status = match error {
        HttpBoundaryError::MissingCredentials | HttpBoundaryError::InsufficientAssurance => {
            StatusCode::UNAUTHORIZED
        }
        HttpBoundaryError::Authenticator(error) if error.is_credential_rejection() => {
            StatusCode::UNAUTHORIZED
        }
        HttpBoundaryError::Authenticator(_) => StatusCode::SERVICE_UNAVAILABLE,
        HttpBoundaryError::BodyTooLarge => StatusCode::PAYLOAD_TOO_LARGE,
        HttpBoundaryError::InvalidContentLength
        | HttpBoundaryError::InvalidRequestId
        | HttpBoundaryError::InvalidCredentials
        | HttpBoundaryError::Csrf => StatusCode::BAD_REQUEST,
        HttpBoundaryError::InvalidContext(_) => StatusCode::SERVICE_UNAVAILABLE,
        _ => StatusCode::SERVICE_UNAVAILABLE,
    };
    if credential_rejection && browser_document_navigation(request) {
        return authentication_redirect(request);
    }
    (status, "Request rejected.").into_response()
}

fn browser_document_navigation(request: &Request) -> bool {
    matches!(*request.method(), http::Method::GET | http::Method::HEAD)
        && !request.uri().path().starts_with("/auth/")
        && request
            .headers()
            .get(http::header::ACCEPT)
            .and_then(|value| value.to_str().ok())
            .is_some_and(|value| {
                value
                    .split(',')
                    .any(|item| item.trim().starts_with("text/html"))
            })
}

fn authentication_redirect(request: &Request) -> Response {
    let location = format!("/auth/required?next={}", request.uri().path());
    let Ok(location) = HeaderValue::from_str(&location) else {
        return internal_error();
    };
    let mut response = StatusCode::SEE_OTHER.into_response();
    response
        .headers_mut()
        .insert(http::header::LOCATION, location);
    response.headers_mut().insert(
        http::header::CACHE_CONTROL,
        HeaderValue::from_static("no-store"),
    );
    response.headers_mut().append(
        http::header::SET_COOKIE,
        HeaderValue::from_static(
            "__Host-session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax; Secure",
        ),
    );
    response.headers_mut().append(
        http::header::SET_COOKIE,
        HeaderValue::from_static(
            "wasi_auth_dev_session=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax",
        ),
    );
    response
}

fn ensure_request_id(request: &mut Request) -> Result<(), StatusCode> {
    let mut values = request.headers().get_all(&REQUEST_ID_HEADER).iter();
    if let Some(value) = values.next() {
        if values.next().is_some() {
            return Err(StatusCode::BAD_REQUEST);
        }
        let valid = value
            .to_str()
            .ok()
            .and_then(|value| RequestId::new(value).ok());
        return valid.map(|_| ()).ok_or(StatusCode::BAD_REQUEST);
    }
    let request_id = format!("request-{}", Uuid::now_v7());
    let header =
        HeaderValue::from_str(&request_id).map_err(|_| StatusCode::INTERNAL_SERVER_ERROR)?;
    request.headers_mut().insert(REQUEST_ID_HEADER, header);
    Ok(())
}

fn backend_uri(origin: &BackendOrigin, original: &Uri) -> Result<Uri, ()> {
    let mut parts = original.clone().into_parts();
    parts.scheme = Some(http::uri::Scheme::HTTP);
    parts.authority = Some(origin.authority.clone());
    Uri::from_parts(parts).map_err(|_| ())
}

fn parse_backend_origin(origin: &str, production: bool) -> Result<BackendOrigin, StartupError> {
    let uri = origin
        .parse::<Uri>()
        .map_err(|_| StartupError::Invalid("AUTH_INGRESS_BACKEND_ORIGIN"))?;
    if uri.scheme_str() != Some("http")
        || uri
            .path_and_query()
            .is_some_and(|value| value.as_str() != "/")
    {
        return Err(StartupError::Invalid("AUTH_INGRESS_BACKEND_ORIGIN"));
    }
    let authority = uri
        .authority()
        .cloned()
        .ok_or(StartupError::Invalid("AUTH_INGRESS_BACKEND_ORIGIN"))?;
    if production
        && !matches!(
            uri.host(),
            Some("127.0.0.1" | "localhost" | "[::1]" | "::1")
        )
    {
        return Err(StartupError::Invalid("AUTH_INGRESS_BACKEND_ORIGIN"));
    }
    let host = HeaderValue::from_str(authority.as_str())
        .map_err(|_| StartupError::Invalid("AUTH_INGRESS_BACKEND_ORIGIN"))?;
    Ok(BackendOrigin { authority, host })
}

fn jwt_key_ring(production: bool) -> Result<JwtKeyRing, StartupError> {
    if let Ok(value) = env::var("AUTH_JWT_KEY_RING_JSON")
        && !value.trim().is_empty()
    {
        return JwtKeyRing::from_json(&value, production)
            .map_err(|_| StartupError::Invalid("AUTH_JWT_KEY_RING_JSON"));
    }
    if production {
        return Err(StartupError::Missing("AUTH_JWT_KEY_RING_JSON"));
    }
    let kid = env::var("AUTH_JWT_KID").unwrap_or_else(|_| "fullstack-app-dev-hs256".to_owned());
    let secret = env::var("AUTH_JWT_SECRET")
        .unwrap_or_else(|_| "dev-fullstack-app-secret-change-me".to_owned());
    JwtKeyRing::development_hs256(kid, secret.into_bytes())
        .map_err(|_| StartupError::Invalid("AUTH_JWT_SECRET"))
}

fn ingress_key() -> Result<[u8; 32], StartupError> {
    let encoded = required("AUTH_TRUSTED_INGRESS_KEY_BASE64")?;
    STANDARD
        .decode(encoded.trim())
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or(StartupError::Invalid("AUTH_TRUSTED_INGRESS_KEY_BASE64"))
}

fn required(name: &'static str) -> Result<String, StartupError> {
    env::var(name)
        .ok()
        .filter(|value| !value.trim().is_empty())
        .ok_or(StartupError::Missing(name))
}

fn bool_env(name: &'static str, default: bool) -> Result<bool, StartupError> {
    match env::var(name).ok().as_deref() {
        None => Ok(default),
        Some("true" | "1") => Ok(true),
        Some("false" | "0") => Ok(false),
        Some(_) => Err(StartupError::Invalid(name)),
    }
}

fn usize_env(
    name: &'static str,
    default: usize,
    minimum: usize,
    maximum: usize,
) -> Result<usize, StartupError> {
    let value = env::var(name)
        .ok()
        .map(|value| value.parse::<usize>())
        .transpose()
        .map_err(|_| StartupError::Invalid(name))?
        .unwrap_or(default);
    (minimum..=maximum)
        .contains(&value)
        .then_some(value)
        .ok_or(StartupError::Invalid(name))
}

fn internal_error() -> Response {
    (
        StatusCode::BAD_GATEWAY,
        "Trusted ingress could not reach the application.",
    )
        .into_response()
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_origin_is_loopback_only_in_production() {
        assert!(parse_backend_origin("http://127.0.0.1:3009", true).is_ok());
        assert!(parse_backend_origin("http://localhost:3009", true).is_ok());
        assert!(parse_backend_origin("http://10.0.0.5:3009", true).is_err());
        assert!(parse_backend_origin("https://127.0.0.1:3009", true).is_err());
        assert!(parse_backend_origin("http://127.0.0.1:3009/base", false).is_err());
    }

    #[test]
    fn backend_uri_preserves_path_and_query() {
        let origin = parse_backend_origin("http://127.0.0.1:3009", false).unwrap();
        let original = Uri::from_static("/api/authorization/check?trace=1");
        let rewritten = backend_uri(&origin, &original).unwrap();
        assert_eq!(
            rewritten,
            Uri::from_static("http://127.0.0.1:3009/api/authorization/check?trace=1")
        );
    }

    #[test]
    fn duplicate_request_ids_are_rejected() {
        let mut request = http::Request::builder()
            .header(&REQUEST_ID_HEADER, "request-one")
            .header(&REQUEST_ID_HEADER, "request-two")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            ensure_request_id(&mut request),
            Err(StatusCode::BAD_REQUEST)
        );
    }

    #[test]
    fn grpc_detection_requires_grpc_content_type() {
        let grpc = http::Request::builder()
            .header(http::header::CONTENT_TYPE, "application/grpc+proto")
            .body(Body::empty())
            .unwrap();
        let ordinary = http::Request::builder()
            .header(http::header::CONTENT_TYPE, "application/json")
            .body(Body::empty())
            .unwrap();
        assert!(is_grpc_request(&grpc));
        assert!(!is_grpc_request(&ordinary));
    }

    #[test]
    fn operational_authentication_failures_are_not_reported_as_bad_credentials() {
        let invalid = NativeAuthenticationError::Token(TokenServiceError::InvalidToken);
        let expired = NativeAuthenticationError::Token(TokenServiceError::ExpiredToken);
        let unavailable = NativeAuthenticationError::Token(TokenServiceError::Crypto);
        let missing = NativeAuthenticationError::Store(PostgresStoreError::Unauthenticated);
        let malformed = NativeAuthenticationError::InvalidCredential;
        let corrupt = NativeAuthenticationError::Store(PostgresStoreError::Context);
        assert!(invalid.is_credential_rejection());
        assert!(expired.is_credential_rejection());
        assert!(missing.is_credential_rejection());
        assert!(malformed.is_credential_rejection());
        assert!(!unavailable.is_credential_rejection());
        assert!(!corrupt.is_credential_rejection());
    }

    #[test]
    fn rejected_browser_session_redirects_and_clears_supported_cookies() {
        let request = http::Request::builder()
            .uri("/dashboard")
            .header(http::header::ACCEPT, "text/html,application/xhtml+xml")
            .body(Body::empty())
            .unwrap();
        let response = boundary_error(
            HttpBoundaryError::Authenticator(NativeAuthenticationError::Token(
                TokenServiceError::InvalidToken,
            )),
            &request,
        );
        let cookies = response
            .headers()
            .get_all(http::header::SET_COOKIE)
            .iter()
            .map(|value| value.to_str().unwrap())
            .collect::<Vec<_>>();

        assert_eq!(response.status(), StatusCode::SEE_OTHER);
        assert_eq!(
            response.headers().get(http::header::LOCATION).unwrap(),
            "/auth/required?next=/dashboard"
        );
        assert_eq!(cookies.len(), 2);
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("__Host-session="))
        );
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("wasi_auth_dev_session="))
        );
    }

    #[test]
    fn rejected_api_session_remains_unauthorized() {
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("/api/authorization/check")
            .header(http::header::ACCEPT, "application/json")
            .body(Body::empty())
            .unwrap();
        let response = boundary_error(
            HttpBoundaryError::Authenticator(NativeAuthenticationError::Token(
                TokenServiceError::InvalidToken,
            )),
            &request,
        );

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert!(response.headers().get(http::header::LOCATION).is_none());
    }

    #[test]
    fn active_cedar_bundle_is_strictly_validated() {
        let valid = ActivePolicyBundle {
            policy_revision: "sha256:test".to_owned(),
            cedar_schema: DEFAULT_APPLICATION_SCHEMA.to_owned(),
            cedar_policy: DEFAULT_APPLICATION_POLICY.to_owned(),
            entities: serde_json::json!([]),
        };
        assert!(cedar_from_active_bundle(valid.clone()).is_ok());
        let invalid = ActivePolicyBundle {
            cedar_schema: "{}".to_owned(),
            ..valid
        };
        assert!(cedar_from_active_bundle(invalid).is_err());
    }
}
