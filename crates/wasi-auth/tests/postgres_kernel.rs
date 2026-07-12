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
        Argon2Policy, EmailVerificationRequest, EmailVerificationResendRequest,
        EmailVerificationService, OutboxSealingKey, PasswordChangeRequest, PasswordLoginRequest,
        PasswordLoginService, PasswordRegistrationRequest, PasswordRegistrationService,
        PasswordResetCompleteRequest, PasswordResetService, PasswordResetStartRequest,
    },
};
#[cfg(feature = "password")]
use wasi_auth::{
    mail::CaptureMailer,
    postgres::{
        management::{
            InvitationService, ManagementError, OrganizationManagementService, UpsertRoleRequest,
        },
        organizations::{CreateOrganizationRequest, OrganizationService},
        outbox::{MailOutboxWorker, PublicBaseUrl},
        rate_limits::RateLimitService,
        sessions::SessionService,
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
        client.batch_execute("BEGIN").await?;
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
        client.batch_execute("COMMIT").await?;

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
            let rate_limits =
                RateLimitService::new(PostgresAuthStore::new(transport.clone()), FixedClock);
            assert!(rate_limits.check("contract", &unique, 2, 60).await?.allowed);
            assert!(rate_limits.check("contract", &unique, 2, 60).await?.allowed);
            let denied = rate_limits.check("contract", &unique, 2, 60).await?;
            assert!(!denied.allowed);
            assert_eq!(denied.retry_after_seconds, 60);
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

            let management = OrganizationManagementService::new(
                PostgresAuthStore::new(transport.clone()),
                FixedClock,
                TestRandom::new(),
            );
            let loaded = management
                .organization(&first.session_id, &organization.organization_id)
                .await?;
            assert_eq!(loaded.organization_id, organization.organization_id);
            let updated = management
                .update_organization(
                    &first.session_id,
                    &organization.organization_id,
                    "Updated Contract Organization",
                    &RequestId::new(format!("update-organization-{unique}"))?,
                )
                .await?;
            assert_eq!(updated.name, "Updated Contract Organization");
            assert_eq!(
                management
                    .list_memberships(&first.session_id, &organization.organization_id)
                    .await?
                    .len(),
                1
            );
            assert_eq!(
                management
                    .list_roles(&first.session_id, &organization.organization_id)
                    .await?
                    .len(),
                4
            );
            let custom_role = management
                .upsert_role(UpsertRoleRequest {
                    session_id: first.session_id.clone(),
                    organization_id: organization.organization_id.clone(),
                    role_id: "billing-editor".to_owned(),
                    name: "Billing Editor".to_owned(),
                    permissions: vec!["organization.view".to_owned(), "counter.view".to_owned()],
                    request_id: RequestId::new(format!("upsert-role-{unique}"))?,
                })
                .await?;
            assert_eq!(custom_role.role_id, "billing-editor");

            let invited_user_id = Uuid::now_v7();
            let invited_unique = invited_user_id.simple().to_string();
            let invited_email = format!("{invited_unique}@example.com");
            store
                .register_password(registration_command_with_credentials(
                    invited_user_id,
                    &invited_unique,
                    &format!("invited-registration-{invited_unique}"),
                    password_hash("invited correct horse battery staple")?,
                    Sha256::digest(format!("invited-token-{invited_unique}").as_bytes()).into(),
                )?)
                .await?;
            let invited_session_id = Uuid::now_v7();
            transport
                .client()
                .execute(
                    "UPDATE auth_users SET status = 'active' WHERE user_id = $1",
                    &[&invited_user_id],
                )
                .await?;
            transport
                .client()
                .execute(
                    "INSERT INTO auth_sessions \
                     (session_id, user_id, assurance, session_revision, user_security_revision, \
                      expires_at_ms, created_at_ms, updated_at_ms) \
                     VALUES ($1, $2, 'aal2', 1, 1, $3, $4, $4)",
                    &[
                        &invited_session_id,
                        &invited_user_id,
                        &1_700_003_600_000_i64,
                        &1_700_000_000_000_i64,
                    ],
                )
                .await?;
            transport
                .client()
                .execute("DELETE FROM auth_outbox", &[])
                .await?;
            let invitation_key = [47_u8; 32];
            let invitations = InvitationService::new(
                PostgresAuthStore::new(transport.clone()),
                FixedClock,
                TestRandom::new(),
                OutboxSealingKey::new("invitation-contract-v1", invitation_key)?,
            );
            let invitation = invitations
                .create(
                    &first.session_id,
                    &organization.organization_id,
                    &invited_email,
                    "member",
                    &RequestId::new(format!("create-invitation-{unique}"))?,
                )
                .await?;
            assert_eq!(invitation.email, invited_email);
            assert_eq!(
                management
                    .list_invitations(&first.session_id, &organization.organization_id)
                    .await?
                    .len(),
                1
            );
            let invitation_mailer = CaptureMailer::default();
            let invitation_worker = MailOutboxWorker::new(
                PostgresAuthStore::new(transport.clone()),
                FixedClock,
                TestRandom::new(),
                OutboxSealingKey::new("invitation-contract-v1", invitation_key)?,
                PublicBaseUrl::new("http://127.0.0.1:3008")?,
            );
            assert_eq!(
                invitation_worker
                    .dispatch(&invitation_mailer, 25)
                    .await?
                    .delivered,
                1
            );
            let invitation_token = invitation_mailer.messages()?[0]
                .message()
                .text_body()
                .split("?token=")
                .nth(1)
                .expect("invitation token")
                .to_owned();
            let invited_session = SessionId::new(invited_session_id.to_string())?;
            let accepted = invitations
                .accept(
                    &invited_session,
                    &invitation_token,
                    &RequestId::new(format!("accept-invitation-{unique}"))?,
                )
                .await?;
            assert_eq!(accepted.organization_id, organization.organization_id);
            let accepted_replay = invitations
                .accept(
                    &invited_session,
                    &invitation_token,
                    &RequestId::new(format!("accept-invitation-replay-{unique}"))?,
                )
                .await?;
            assert_eq!(
                accepted_replay.organization_id,
                organization.organization_id
            );
            let assigned = management
                .assign_role(
                    &first.session_id,
                    &organization.organization_id,
                    &invited_user_id.to_string(),
                    "billing-editor",
                    &RequestId::new(format!("assign-role-{unique}"))?,
                )
                .await?;
            assert_eq!(assigned.role_id, "billing-editor");
            management
                .remove_member(
                    &first.session_id,
                    &organization.organization_id,
                    &invited_user_id.to_string(),
                    &RequestId::new(format!("remove-member-{unique}"))?,
                )
                .await?;
            assert!(matches!(
                management
                    .remove_member(
                        &first.session_id,
                        &organization.organization_id,
                        &user_id.to_string(),
                        &RequestId::new(format!("remove-final-owner-{unique}"))?,
                    )
                    .await,
                Err(ManagementError::ProtectedInvariant)
            ));
            let audit = management
                .list_audit_events(
                    &first.session_id,
                    Some(&organization.organization_id),
                    0,
                    100,
                )
                .await?;
            assert!(
                audit
                    .events
                    .iter()
                    .any(|event| event.action == "member.remove")
            );

            transport
                .client()
                .execute(
                    "INSERT INTO auth_system_administrators \
                     (user_id, granted_by, granted_at_ms) VALUES ($1, $1, $2) \
                     ON CONFLICT (user_id) DO UPDATE SET revoked_at_ms = NULL",
                    &[&user_id, &1_700_000_000_000_i64],
                )
                .await?;
            assert!(
                management
                    .list_admin_users(&first.session_id)
                    .await?
                    .iter()
                    .any(|user| user.user_id == invited_user_id.to_string())
            );
            let disabled = management
                .set_user_disabled(
                    &first.session_id,
                    &invited_user_id.to_string(),
                    true,
                    &RequestId::new(format!("disable-user-{unique}"))?,
                )
                .await?;
            assert_eq!(disabled.status, "disabled");
            assert!(matches!(
                management
                    .set_user_disabled(
                        &first.session_id,
                        &user_id.to_string(),
                        true,
                        &RequestId::new(format!("disable-final-owner-{unique}"))?,
                    )
                    .await,
                Err(ManagementError::ProtectedInvariant)
            ));

            let reset_key = [29_u8; 32];
            let reset_service = PasswordResetService::new(
                PostgresAuthStore::new(transport.clone()),
                FixedClock,
                TestRandom::new(),
                Argon2Policy::default(),
                OutboxSealingKey::new("reset-contract-v1", reset_key)?,
            );
            let reset_start = reset_service
                .start(PasswordResetStartRequest::new(
                    format!("{unique}@example.com"),
                    "/organizations",
                    RequestId::new(format!("reset-start-{unique}"))?,
                ))
                .await?;
            assert!(reset_start.accepted);
            let reset_mailer = CaptureMailer::default();
            let reset_worker = MailOutboxWorker::new(
                PostgresAuthStore::new(transport.clone()),
                FixedClock,
                TestRandom::new(),
                OutboxSealingKey::new("reset-contract-v1", reset_key)?,
                PublicBaseUrl::new("http://127.0.0.1:3008")?,
            );
            let reset_report = reset_worker.dispatch(&reset_mailer, 25).await?;
            assert_eq!(reset_report.delivered, 1);
            let reset_messages = reset_mailer.messages()?;
            let reset_body = reset_messages
                .iter()
                .find(|message| {
                    message.message().kind() == wasi_auth::mail::EmailKind::PasswordReset
                })
                .expect("password reset mail")
                .message()
                .text_body();
            let reset_token = reset_body
                .split("?token=")
                .nth(1)
                .expect("reset token")
                .to_owned();
            let new_password = "an entirely new correct password";
            let completed_reset = reset_service
                .complete(PasswordResetCompleteRequest::new(
                    reset_token.clone(),
                    new_password,
                    RequestId::new(format!("reset-complete-{unique}"))?,
                    "/organizations",
                ))
                .await?;
            assert!(!completed_reset.replayed);
            let replayed_reset = reset_service
                .complete(PasswordResetCompleteRequest::new(
                    reset_token,
                    new_password,
                    RequestId::new(format!("reset-replay-{unique}"))?,
                    "/organizations",
                ))
                .await?;
            assert!(replayed_reset.replayed);
            assert_eq!(replayed_reset.session_id, completed_reset.session_id);

            let login = PasswordLoginService::new(
                PostgresAuthStore::new(transport.clone()),
                FixedClock,
                TestRandom::new(),
                Argon2Policy::default(),
            );
            let login = login
                .login(PasswordLoginRequest::new(
                    format!("{unique}@example.com"),
                    new_password,
                    RequestId::new(format!("login-{unique}"))?,
                    "/organizations",
                ))
                .await?;
            assert_eq!(login.user_id.as_str(), user_id.to_string());
            let session_service = SessionService::new(
                PostgresAuthStore::new(NativePostgresTransport::connect(&database_url).await?),
                FixedClock,
                TestRandom::new(),
            );
            let sessions = session_service
                .list(&UserId::new(user_id.to_string())?)
                .await?;
            assert!(
                sessions
                    .iter()
                    .any(|session| session.session_id == login.session_id)
            );
            session_service
                .revoke(
                    &login.session_id,
                    &completed_reset.session_id,
                    &RequestId::new(format!("revoke-login-{unique}"))?,
                )
                .await?;
            let sessions = session_service
                .list(&UserId::new(user_id.to_string())?)
                .await?;
            assert!(
                sessions
                    .iter()
                    .all(|session| session.session_id != login.session_id)
            );

            transport
                .client()
                .execute(
                    "UPDATE auth_sessions SET assurance = 'aal2' WHERE session_id = $1",
                    &[&Uuid::parse_str(completed_reset.session_id.as_str())?],
                )
                .await?;
            let changed_password = "the final high assurance password";
            PasswordLoginService::new(
                PostgresAuthStore::new(transport.clone()),
                FixedClock,
                TestRandom::new(),
                Argon2Policy::default(),
            )
            .change_password(PasswordChangeRequest::new(
                UserId::new(user_id.to_string())?,
                completed_reset.session_id.clone(),
                new_password,
                changed_password,
                RequestId::new(format!("password-change-{unique}"))?,
            ))
            .await?;
            let sessions = session_service
                .list(&UserId::new(user_id.to_string())?)
                .await?;
            assert_eq!(sessions.len(), 1);
            assert_eq!(sessions[0].session_id, completed_reset.session_id);

            let changed_login = PasswordLoginService::new(
                PostgresAuthStore::new(transport),
                FixedClock,
                TestRandom::new(),
                Argon2Policy::default(),
            )
            .login(PasswordLoginRequest::new(
                format!("{unique}@example.com"),
                changed_password,
                RequestId::new(format!("changed-login-{unique}"))?,
                "/organizations",
            ))
            .await?;
            assert_eq!(changed_login.user_id.as_str(), user_id.to_string());

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
            registration
                .resend_verification(EmailVerificationResendRequest::new(
                    email.clone(),
                    RequestId::new(format!("registration-resend-{unique}"))?,
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
            assert_eq!(report.delivered, 2);
            let messages = mailer.messages()?;
            assert_eq!(messages.len(), 2);
            assert!(messages.iter().all(|message| {
                message.message().recipient().as_str() == email
                    && message
                        .message()
                        .text_body()
                        .contains("/verify-email?token=")
            }));

            transport
                .client()
                .execute(
                    "UPDATE auth_users SET status = 'active' WHERE user_id = $1",
                    &[&Uuid::parse_str(receipt.user_id.as_str())?],
                )
                .await?;
            registration
                .resend_verification(EmailVerificationResendRequest::new(
                    email.clone(),
                    RequestId::new(format!("active-resend-{unique}"))?,
                    "/organizations",
                ))
                .await?;
            let no_mail = worker.dispatch(&mailer, 25).await?;
            assert_eq!(no_mail.leased, 0);

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

#[cfg(feature = "password")]
#[test]
fn live_postgres_final_owner_concurrency_contract() -> Result<(), Box<dyn Error>> {
    let Ok(database_url) = std::env::var("WASI_AUTH_POSTGRES_TEST_URL") else {
        return Ok(());
    };
    let _live_database = LIVE_DB_LOCK.lock().expect("live database lock");
    Builder::new_current_thread()
        .enable_io()
        .build()?
        .block_on(async {
            let first_transport = NativePostgresTransport::connect(&database_url).await?;
            let second_transport = NativePostgresTransport::connect(&database_url).await?;
            let owner_a = Uuid::now_v7();
            let owner_b = Uuid::now_v7();
            let organization_id = Uuid::now_v7();
            let session_a = Uuid::now_v7();
            let session_b = Uuid::now_v7();
            let now_ms = 1_700_000_000_000_i64;
            let client = first_transport.client();
            client.batch_execute("BEGIN").await?;
            for (user_id, email) in [
                (owner_a, format!("{}@example.com", owner_a.simple())),
                (owner_b, format!("{}@example.com", owner_b.simple())),
            ] {
                client
                    .execute(
                        "INSERT INTO auth_users \
                         (user_id, normalized_email, primary_email, status, security_revision, \
                          created_at_ms, updated_at_ms) \
                         VALUES ($1, $2, $2, 'active', 1, $3, $3)",
                        &[&user_id, &email, &now_ms],
                    )
                    .await?;
            }
            client
                .execute(
                    "INSERT INTO auth_organizations \
                     (organization_id, name, status, authorization_revision, created_by, \
                      created_at_ms, updated_at_ms) \
                     VALUES ($1, 'Concurrent Owners', 'active', 1, $2, $3, $3)",
                    &[&organization_id, &owner_a, &now_ms],
                )
                .await?;
            client
                .execute(
                    "INSERT INTO auth_roles \
                     (organization_id, role_id, name, built_in, created_at_ms, updated_at_ms) \
                     VALUES ($1, 'owner', 'Owner', TRUE, $2, $2), \
                            ($1, 'member', 'Member', TRUE, $2, $2)",
                    &[&organization_id, &now_ms],
                )
                .await?;
            client
                .execute(
                    "INSERT INTO auth_role_permissions (organization_id, role_id, permission) \
                     VALUES ($1, 'owner', 'member.manage'), \
                            ($1, 'owner', 'ownership.transfer')",
                    &[&organization_id],
                )
                .await?;
            for user_id in [owner_a, owner_b] {
                client
                    .execute(
                        "INSERT INTO auth_memberships \
                         (organization_id, user_id, role_id, status, joined_at_ms, updated_at_ms) \
                         VALUES ($1, $2, 'owner', 'active', $3, $3)",
                        &[&organization_id, &user_id, &now_ms],
                    )
                    .await?;
            }
            for (session_id, user_id) in [(session_a, owner_a), (session_b, owner_b)] {
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
                            &(now_ms + 3_600_000),
                            &now_ms,
                        ],
                    )
                    .await?;
            }
            client.batch_execute("COMMIT").await?;

            let first = OrganizationManagementService::new(
                PostgresAuthStore::new(first_transport.clone()),
                FixedClock,
                TestRandom::new(),
            );
            let second = OrganizationManagementService::new(
                PostgresAuthStore::new(second_transport),
                FixedClock,
                TestRandom::new(),
            );
            let session_a = SessionId::new(session_a.to_string())?;
            let session_b = SessionId::new(session_b.to_string())?;
            let organization_id_text = organization_id.to_string();
            let owner_a_text = owner_a.to_string();
            let owner_b_text = owner_b.to_string();
            let demote_request_id = RequestId::new("concurrent-owner-demote")?;
            let remove_request_id = RequestId::new("concurrent-owner-remove")?;
            let demote = first.assign_role(
                &session_a,
                &organization_id_text,
                &owner_b_text,
                "member",
                &demote_request_id,
            );
            let remove = second.remove_member(
                &session_b,
                &organization_id_text,
                &owner_a_text,
                &remove_request_id,
            );
            let (demote, remove) = futures::future::join(demote, remove).await;
            assert_eq!(usize::from(demote.is_ok()) + usize::from(remove.is_ok()), 1);
            assert!(
                [demote.err(), remove.err()]
                    .into_iter()
                    .flatten()
                    .any(|error| matches!(error, ManagementError::ProtectedInvariant))
            );
            let remaining_owners: i64 = client
                .query_one(
                    "SELECT count(*) FROM auth_memberships \
                     WHERE organization_id = $1 AND role_id = 'owner' AND status = 'active'",
                    &[&organization_id],
                )
                .await?
                .get(0);
            assert_eq!(remaining_owners, 1);

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
