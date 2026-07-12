//! Live PostgreSQL contract for the relational authentication kernel.
#![cfg(feature = "postgres-native")]

#[cfg(feature = "password")]
use std::convert::Infallible;
use std::{error::Error, sync::Mutex};

#[cfg(feature = "password")]
use argon2::{Algorithm, Argon2, Params, Version};
#[cfg(feature = "password")]
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
#[cfg(feature = "password")]
use sha2::{Digest, Sha256};
use tokio::runtime::Builder;
use uuid::Uuid;
#[cfg(feature = "password")]
use wasi_auth::context::UserId;
use wasi_auth::context::{RequestId, SessionId};
use wasi_auth::postgres::native::NativePostgresTransport;
use wasi_auth::postgres::{
    CommandContext, PostgresAuthStore, RegisterPasswordCommand, SealedPayload,
};
#[cfg(feature = "password")]
use wasi_auth::{
    authentication::{Clock, RandomSource},
    postgres::workflows::{
        Argon2Policy, EmailVerificationRequest, EmailVerificationService, OutboxSealingKey,
        PasswordLoginRequest, PasswordLoginService, PasswordRegistrationRequest,
        PasswordRegistrationService,
    },
};
#[cfg(feature = "password")]
use wasi_auth::{
    mail::CaptureMailer,
    postgres::{
        organizations::{CreateOrganizationRequest, OrganizationService},
        outbox::{MailOutboxWorker, PublicBaseUrl},
    },
};

static LIVE_DB_LOCK: Mutex<()> = Mutex::new(());

#[test]
fn live_postgres_registration_and_context_contract() -> Result<(), Box<dyn Error>> {
    let Ok(database_url) = std::env::var("WASI_AUTH_POSTGRES_TEST_URL") else {
        return Ok(());
    };
    let _live_database = LIVE_DB_LOCK.lock().expect("live database lock");
    Builder::new_current_thread().enable_io().build()?.block_on(async {
        let transport = NativePostgresTransport::connect(&database_url).await?;
        let store = PostgresAuthStore::new(transport.clone());
        let user_id = Uuid::now_v7();
        let unique = user_id.simple().to_string();
        let idempotency_key = format!("registration-contract-{unique}");
        let command = registration_command(user_id, &unique, &idempotency_key)?;

        let created = store.register_password(command).await?;
        assert_eq!(created.user_id.as_str(), user_id.to_string());
        assert!(!created.replayed);

        let replayed = store
            .register_password(registration_command(
                user_id,
                &unique,
                &idempotency_key,
            )?)
            .await?;
        assert!(replayed.replayed);

        let organization_id = Uuid::now_v7();
        let session_id = Uuid::now_v7();
        let now_ms = 1_700_000_000_000_i64;
        let client = transport.client();
        client
            .execute(
                "UPDATE auth_users SET status = 'active' WHERE user_id = $1",
                &[&user_id],
            )
            .await?;
        client
            .execute(
                "INSERT INTO auth_organizations \
                 (organization_id, name, status, authorization_revision, created_by, created_at_ms, updated_at_ms) \
                 VALUES ($1, 'Contract Organization', 'active', 1, $2, $3, $3)",
                &[&organization_id, &user_id, &now_ms],
            )
            .await?;
        client
            .execute(
                "INSERT INTO auth_roles \
                 (organization_id, role_id, name, built_in, created_at_ms, updated_at_ms) \
                 VALUES ($1, 'owner', 'Owner', TRUE, $2, $2)",
                &[&organization_id, &now_ms],
            )
            .await?;
        client
            .execute(
                "INSERT INTO auth_role_permissions (organization_id, role_id, permission) \
                 VALUES ($1, 'owner', 'organization.view')",
                &[&organization_id],
            )
            .await?;
        client
            .execute(
                "INSERT INTO auth_memberships \
                 (organization_id, user_id, role_id, status, joined_at_ms, updated_at_ms) \
                 VALUES ($1, $2, 'owner', 'active', $3, $3)",
                &[&organization_id, &user_id, &now_ms],
            )
            .await?;
        client
            .execute(
                "INSERT INTO auth_sessions \
                 (session_id, user_id, selected_organization_id, assurance, session_revision, \
                  user_security_revision, expires_at_ms, created_at_ms, updated_at_ms) \
                 VALUES ($1, $2, $3, 'aal2', 1, 1, $4, $5, $5)",
                &[
                    &session_id,
                    &user_id,
                    &organization_id,
                    &(now_ms + 7_200_000),
                    &now_ms,
                ],
            )
            .await?;

        let context = store
            .load_request_context(
                &SessionId::new(session_id.to_string())?,
                RequestId::new("postgres-contract-request")?,
                (now_ms as u64) / 1_000,
            )
            .await?;
        assert_eq!(context.auth().principal().user_id().as_str(), user_id.to_string());
        assert!(
            context
                .authorization()
                .has_permission("organization.view")
        );
        assert_eq!(
            context.auth().organization_id().map(ToString::to_string),
            Some(organization_id.to_string())
        );

        Ok::<_, Box<dyn Error>>(())
    })
}

#[cfg(feature = "password")]
#[test]
fn live_postgres_verification_replay_and_password_login() -> Result<(), Box<dyn Error>> {
    let Ok(database_url) = std::env::var("WASI_AUTH_POSTGRES_TEST_URL") else {
        return Ok(());
    };
    let _live_database = LIVE_DB_LOCK.lock().expect("live database lock");
    Builder::new_current_thread()
        .enable_io()
        .build()?
        .block_on(async {
            let transport = NativePostgresTransport::connect(&database_url).await?;
            let store = PostgresAuthStore::new(transport.clone());
            let user_id = Uuid::now_v7();
            let unique = user_id.simple().to_string();
            let raw_token = format!("verification-{unique}");
            let password = "correct horse battery staple";
            let idempotency_key = format!("registration-workflow-{unique}");
            let command = registration_command_with_credentials(
                user_id,
                &unique,
                &idempotency_key,
                password_hash(password)?,
                Sha256::digest(raw_token.as_bytes()).into(),
            )?;
            store.register_password(command).await?;

            let verification = EmailVerificationService::new(
                PostgresAuthStore::new(transport.clone()),
                FixedClock,
                TestRandom::new(),
            );
            let first = verification
                .verify(EmailVerificationRequest::new(
                    raw_token.clone(),
                    RequestId::new(format!("verify-{unique}"))?,
                    "/organizations",
                ))
                .await?;
            assert!(!first.replayed);

            let replayed = verification
                .verify(EmailVerificationRequest::new(
                    raw_token,
                    RequestId::new(format!("verify-replay-{unique}"))?,
                    "/organizations",
                ))
                .await?;
            assert!(replayed.replayed);
            assert_eq!(replayed.session_id, first.session_id);

            transport
                .client()
                .execute(
                    "UPDATE auth_sessions SET assurance = 'aal2' WHERE session_id = $1",
                    &[&Uuid::parse_str(first.session_id.as_str())?],
                )
                .await?;
            let organization_service = OrganizationService::new(
                PostgresAuthStore::new(transport.clone()),
                FixedClock,
                TestRandom::new(),
            );
            let create_request = || CreateOrganizationRequest {
                idempotency_key: format!("create-organization-{unique}"),
                session_id: first.session_id.clone(),
                name: "Contract Organization".to_owned(),
                request_id: RequestId::new(format!("create-organization-{unique}"))
                    .expect("request id"),
            };
            let organization = organization_service.create(create_request()).await?;
            assert_eq!(organization.role_id, "owner");
            assert!(
                organization
                    .permissions
                    .iter()
                    .any(|permission| permission == "ownership.transfer")
            );
            let replayed_organization = organization_service.create(create_request()).await?;
            assert_eq!(
                replayed_organization.organization_id,
                organization.organization_id
            );
            let organizations = organization_service
                .list(&UserId::new(user_id.to_string())?)
                .await?;
            assert!(
                organizations
                    .iter()
                    .any(|candidate| candidate.organization_id == organization.organization_id)
            );

            let login = PasswordLoginService::new(
                PostgresAuthStore::new(transport),
                FixedClock,
                TestRandom::new(),
                Argon2Policy::default(),
            );
            let login = login
                .login(PasswordLoginRequest::new(
                    format!("{unique}@example.com"),
                    password,
                    RequestId::new(format!("login-{unique}"))?,
                    "/organizations",
                ))
                .await?;
            assert_eq!(login.user_id.as_str(), user_id.to_string());

            Ok::<_, Box<dyn Error>>(())
        })
}

#[cfg(feature = "password")]
#[test]
fn live_postgres_registration_mail_outbox_contract() -> Result<(), Box<dyn Error>> {
    let Ok(database_url) = std::env::var("WASI_AUTH_POSTGRES_TEST_URL") else {
        return Ok(());
    };
    let _live_database = LIVE_DB_LOCK.lock().expect("live database lock");
    Builder::new_current_thread()
        .enable_io()
        .build()?
        .block_on(async {
            let transport = NativePostgresTransport::connect(&database_url).await?;
            transport
                .client()
                .execute("DELETE FROM auth_outbox", &[])
                .await?;
            let unique = Uuid::now_v7().simple().to_string();
            let email = format!("{unique}@example.com");
            let key = [17_u8; 32];
            let registration = PasswordRegistrationService::new(
                PostgresAuthStore::new(transport.clone()),
                FixedClock,
                TestRandom::new(),
                Argon2Policy::default(),
                OutboxSealingKey::new("outbox-contract-v1", key)?,
            );
            let receipt = registration
                .register(PasswordRegistrationRequest::new(
                    format!("registration-mail-{unique}"),
                    format!("anonymous:{unique}"),
                    RequestId::new(format!("registration-mail-{unique}"))?,
                    email.clone(),
                    "correct horse battery staple",
                    "/organizations",
                ))
                .await?;

            let worker = MailOutboxWorker::new(
                PostgresAuthStore::new(transport.clone()),
                FixedClock,
                TestRandom::new(),
                OutboxSealingKey::new("outbox-contract-v1", key)?,
                PublicBaseUrl::new("http://127.0.0.1:3008")?,
            );
            let mailer = CaptureMailer::default();
            let report = worker.dispatch(&mailer, 25).await?;
            assert_eq!(report.delivered, 1);
            let messages = mailer.messages()?;
            assert_eq!(messages.len(), 1);
            assert_eq!(messages[0].message().recipient().as_str(), email);
            assert!(
                messages[0]
                    .message()
                    .text_body()
                    .contains("/verify-email?token=")
            );

            let row = transport
                .client()
                .query_one(
                    "SELECT status, delivery_id FROM auth_outbox \
                 WHERE deduplication_key = $1",
                    &[&format!("email-verification:{}:v1", receipt.user_id)],
                )
                .await?;
            assert_eq!(row.get::<_, String>("status"), "delivered");
            assert_eq!(row.get::<_, String>("delivery_id"), "capture-1");

            Ok::<_, Box<dyn Error>>(())
        })
}

fn registration_command(
    user_id: Uuid,
    unique: &str,
    idempotency_key: &str,
) -> Result<RegisterPasswordCommand, Box<dyn Error>> {
    let mut verification_token_hash = [0_u8; 32];
    verification_token_hash.copy_from_slice(&unique.as_bytes()[..32]);
    Ok(RegisterPasswordCommand {
        context: CommandContext::new(
            idempotency_key,
            format!("anonymous:{unique}"),
            [3; 32],
            RequestId::new(format!("request-{unique}"))?,
            1_700_000_000_000,
            1_700_086_400_000,
        )?,
        user_id,
        normalized_email: format!("{unique}@example.com"),
        primary_email: format!("{unique}@example.com"),
        password_hash: "$argon2id$v=19$m=65536,t=3,p=1$contract".to_owned(),
        verification_token_hash,
        redirect_uri: "/verify-email".to_owned(),
        verification_expires_at_ms: 1_700_000_900_000,
        outbox_id: Uuid::now_v7(),
        outbox_deduplication_key: format!("verify:{unique}:v1"),
        outbox_payload: SealedPayload::new("test-key-v1", [5; 64])?,
        audit_id: Uuid::now_v7(),
        audit_metadata: serde_json::json!({"test":true}),
    })
}

#[cfg(feature = "password")]
fn registration_command_with_credentials(
    user_id: Uuid,
    unique: &str,
    idempotency_key: &str,
    password_hash: String,
    verification_token_hash: [u8; 32],
) -> Result<RegisterPasswordCommand, Box<dyn Error>> {
    let mut command = registration_command(user_id, unique, idempotency_key)?;
    command.password_hash = password_hash;
    command.verification_token_hash = verification_token_hash;
    Ok(command)
}

#[cfg(feature = "password")]
fn password_hash(password: &str) -> Result<String, Box<dyn Error>> {
    let params = Params::new(19_456, 2, 1, Some(32))
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    let mut output = [0_u8; 32];
    let salt = [9_u8; 16];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), &salt, &mut output)
        .map_err(|error| std::io::Error::other(error.to_string()))?;
    Ok(format!(
        "argon2id$m=19456,t=2,p=1${}${}",
        URL_SAFE_NO_PAD.encode(salt),
        URL_SAFE_NO_PAD.encode(output),
    ))
}

#[cfg(feature = "password")]
#[derive(Clone, Copy, Debug)]
struct FixedClock;

#[cfg(feature = "password")]
impl Clock for FixedClock {
    fn now_unix_seconds(&self) -> u64 {
        1_700_000_000
    }
}

#[cfg(feature = "password")]
#[derive(Debug)]
struct TestRandom(Mutex<u128>);

#[cfg(feature = "password")]
impl TestRandom {
    fn new() -> Self {
        Self(Mutex::new(Uuid::now_v7().as_u128()))
    }
}

#[cfg(feature = "password")]
impl RandomSource for TestRandom {
    type Error = Infallible;

    fn fill_bytes(&self, destination: &mut [u8]) -> Result<(), Self::Error> {
        let mut state = self.0.lock().expect("test random lock");
        for byte in destination {
            *state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            *byte = (*state >> 64) as u8;
        }
        Ok(())
    }
}
