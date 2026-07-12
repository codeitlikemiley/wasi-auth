BEGIN;

CREATE TABLE IF NOT EXISTS auth_schema_migrations (
    version TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at_ms BIGINT NOT NULL
);

-- Generic DDD event stream and checkpoints used by the reference fullstack
-- adapter. Secret material is never written to this stream.
CREATE TABLE IF NOT EXISTS events (
    sequence BIGSERIAL PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    aggregate_id TEXT NOT NULL,
    aggregate_type TEXT NOT NULL,
    revision BIGINT NOT NULL,
    event_type TEXT NOT NULL,
    event_version BIGINT NOT NULL,
    payload TEXT NOT NULL,
    metadata TEXT NOT NULL,
    recorded_at_ms BIGINT NOT NULL,
    UNIQUE (aggregate_type, aggregate_id, revision)
);

CREATE INDEX IF NOT EXISTS idx_auth_events_aggregate
    ON events (aggregate_type, aggregate_id);

CREATE INDEX IF NOT EXISTS idx_auth_events_type_sequence
    ON events (aggregate_type, sequence);

CREATE TABLE IF NOT EXISTS checkpoints (
    projection_name TEXT PRIMARY KEY,
    last_sequence BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_events (
    sequence BIGSERIAL PRIMARY KEY,
    event_id TEXT NOT NULL UNIQUE,
    aggregate_type TEXT NOT NULL,
    aggregate_id TEXT NOT NULL,
    revision BIGINT NOT NULL CHECK (revision > 0),
    event_type TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    recorded_at_ms BIGINT NOT NULL,
    UNIQUE (aggregate_type, aggregate_id, revision)
);

CREATE INDEX IF NOT EXISTS auth_events_global_idx
    ON auth_events (sequence);

CREATE TABLE IF NOT EXISTS auth_projection_records (
    projection TEXT NOT NULL,
    record_key TEXT NOT NULL,
    value_json TEXT NOT NULL,
    source_sequence BIGINT NOT NULL REFERENCES auth_events(sequence),
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (projection, record_key)
);

CREATE TABLE IF NOT EXISTS auth_users (
    user_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    primary_email TEXT NOT NULL,
    disabled BIGINT NOT NULL DEFAULT 0 CHECK (disabled IN (0, 1)),
    email_verified BIGINT NOT NULL DEFAULT 0 CHECK (email_verified IN (0, 1)),
    security_revision BIGINT NOT NULL DEFAULT 1,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_users_by_email (
    tenant_id TEXT NOT NULL,
    normalized_email TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES auth_users(user_id),
    PRIMARY KEY (tenant_id, normalized_email)
);

CREATE TABLE IF NOT EXISTS auth_organizations (
    organization_id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'archived')),
    authorization_revision BIGINT NOT NULL DEFAULT 1,
    created_by TEXT NOT NULL REFERENCES auth_users(user_id),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_roles (
    role_id TEXT NOT NULL,
    organization_id TEXT NOT NULL REFERENCES auth_organizations(organization_id),
    name TEXT NOT NULL,
    built_in BIGINT NOT NULL DEFAULT 0 CHECK (built_in IN (0, 1)),
    permissions_json TEXT NOT NULL DEFAULT '[]',
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (organization_id, role_id),
    UNIQUE (organization_id, name)
);

CREATE TABLE IF NOT EXISTS auth_role_permissions (
    organization_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    PRIMARY KEY (organization_id, role_id, permission),
    FOREIGN KEY (organization_id, role_id)
        REFERENCES auth_roles(organization_id, role_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_memberships (
    organization_id TEXT NOT NULL REFERENCES auth_organizations(organization_id),
    user_id TEXT NOT NULL REFERENCES auth_users(user_id),
    role_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'blocked', 'removed')),
    joined_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (organization_id, user_id),
    FOREIGN KEY (organization_id, role_id)
        REFERENCES auth_roles(organization_id, role_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_memberships_user
    ON auth_memberships (user_id, status);

CREATE TABLE IF NOT EXISTS auth_membership_roles (
    organization_id TEXT NOT NULL,
    user_id TEXT NOT NULL,
    role_id TEXT NOT NULL,
    PRIMARY KEY (organization_id, user_id, role_id),
    FOREIGN KEY (organization_id, user_id)
        REFERENCES auth_memberships(organization_id, user_id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id, role_id)
        REFERENCES auth_roles(organization_id, role_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS auth_invitations (
    invitation_id TEXT PRIMARY KEY,
    organization_id TEXT NOT NULL REFERENCES auth_organizations(organization_id),
    normalized_email TEXT NOT NULL,
    role_id TEXT NOT NULL,
    token_hash TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    accepted_at_ms BIGINT,
    created_by TEXT NOT NULL REFERENCES auth_users(user_id),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    FOREIGN KEY (organization_id, role_id)
        REFERENCES auth_roles(organization_id, role_id)
);

CREATE INDEX IF NOT EXISTS auth_invitations_org_email_idx
    ON auth_invitations (organization_id, normalized_email);

CREATE INDEX IF NOT EXISTS idx_auth_invitations_org
    ON auth_invitations (organization_id, status);

CREATE TABLE IF NOT EXISTS auth_audit_events (
    sequence BIGSERIAL PRIMARY KEY,
    organization_id TEXT,
    actor_user_id TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    recorded_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_auth_audit_org_sequence
    ON auth_audit_events (organization_id, sequence);

CREATE TABLE IF NOT EXISTS auth_policy_versions (
    version_id TEXT PRIMARY KEY,
    status TEXT NOT NULL,
    policy_hash TEXT NOT NULL UNIQUE,
    policy_text TEXT NOT NULL,
    schema_text TEXT NOT NULL,
    published_by TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_credentials (
    credential_id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES auth_users(user_id),
    kind TEXT NOT NULL CHECK (kind IN ('password', 'oauth', 'passkey', 'totp', 'recovery_code')),
    secret_version BIGINT NOT NULL CHECK (secret_version > 0),
    status TEXT NOT NULL CHECK (status IN ('active', 'revoked')),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_secret_records (
    credential_id TEXT NOT NULL REFERENCES auth_credentials(credential_id) ON DELETE CASCADE,
    secret_version BIGINT NOT NULL,
    key_version TEXT NOT NULL,
    encrypted_material BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (credential_id, secret_version)
);

CREATE TABLE IF NOT EXISTS auth_external_identities (
    tenant_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES auth_users(user_id),
    primary_email TEXT,
    profile_json TEXT NOT NULL DEFAULT '{}',
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, provider_id, provider_subject)
);

CREATE TABLE IF NOT EXISTS auth_password_credentials (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES auth_users(user_id),
    password_hash TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT,
    last_authenticated_at_ms BIGINT,
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS auth_oauth_transactions (
    transaction_id TEXT PRIMARY KEY,
    provider_id TEXT NOT NULL,
    state_hash BYTEA NOT NULL UNIQUE,
    nonce_hash BYTEA NOT NULL,
    pkce_verifier_encrypted BYTEA NOT NULL,
    redirect_uri TEXT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    completed_at_ms BIGINT
);

CREATE TABLE IF NOT EXISTS auth_webauthn_challenges (
    challenge_id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES auth_users(user_id),
    challenge_hash BYTEA NOT NULL UNIQUE,
    ceremony TEXT NOT NULL CHECK (ceremony IN ('registration', 'authentication')),
    rp_id TEXT NOT NULL,
    origin TEXT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    completed_at_ms BIGINT
);

CREATE TABLE IF NOT EXISTS auth_passkeys (
    credential_id TEXT PRIMARY KEY REFERENCES auth_credentials(credential_id) ON DELETE CASCADE,
    webauthn_credential_id BYTEA NOT NULL UNIQUE,
    public_key_cose BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0,
    transports_json TEXT NOT NULL DEFAULT '[]',
    display_name TEXT NOT NULL,
    last_used_at_ms BIGINT
);

CREATE TABLE IF NOT EXISTS auth_passkey_credentials (
    tenant_id TEXT NOT NULL,
    credential_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES auth_users(user_id),
    public_key_json TEXT NOT NULL,
    transports_json TEXT NOT NULL DEFAULT '[]',
    sign_count BIGINT NOT NULL DEFAULT 0,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, credential_id)
);

CREATE INDEX IF NOT EXISTS idx_auth_passkey_credentials_user
    ON auth_passkey_credentials (tenant_id, user_id);

CREATE TABLE IF NOT EXISTS auth_mfa_factors (
    credential_id TEXT PRIMARY KEY REFERENCES auth_credentials(credential_id) ON DELETE CASCADE,
    confirmed_at_ms BIGINT,
    last_used_at_ms BIGINT
);

CREATE TABLE IF NOT EXISTS auth_mfa_totp (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES auth_users(user_id),
    credential_id TEXT NOT NULL,
    encrypted_secret TEXT NOT NULL,
    confirmed_at_ms BIGINT,
    last_used_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, user_id)
);

CREATE TABLE IF NOT EXISTS auth_recovery_codes (
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES auth_users(user_id),
    credential_id TEXT NOT NULL,
    code_hash TEXT NOT NULL,
    used_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, user_id, code_hash)
);

CREATE INDEX IF NOT EXISTS idx_auth_recovery_codes_available
    ON auth_recovery_codes (tenant_id, user_id, used_at_ms);

CREATE TABLE IF NOT EXISTS auth_sessions (
    session_id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    user_id TEXT NOT NULL REFERENCES auth_users(user_id),
    primary_email TEXT,
    assurance TEXT NOT NULL CHECK (assurance IN ('aal1', 'aal2')),
    permissions_json TEXT NOT NULL DEFAULT '[]',
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT
);

CREATE INDEX IF NOT EXISTS auth_sessions_user_active_idx
    ON auth_sessions (user_id, revoked_at_ms, expires_at_ms);

CREATE TABLE IF NOT EXISTS auth_refresh_token_hashes (
    tenant_id TEXT NOT NULL,
    token_hash TEXT NOT NULL,
    session_id TEXT NOT NULL REFERENCES auth_sessions(session_id),
    expires_at_ms BIGINT NOT NULL,
    rotated_at_ms BIGINT,
    revoked_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, token_hash)
);

CREATE TABLE IF NOT EXISTS auth_one_time_grants (
    grant_id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES auth_users(user_id),
    kind TEXT NOT NULL CHECK (kind IN ('email_verification', 'password_reset', 'invitation')),
    token_hash BYTEA NOT NULL UNIQUE,
    expires_at_ms BIGINT NOT NULL,
    consumed_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_token_grants (
    grant_id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL UNIQUE,
    tenant_id TEXT NOT NULL,
    grant_type TEXT NOT NULL,
    subject_hint TEXT,
    redirect_url TEXT NOT NULL,
    payload_json TEXT NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    consumed_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_provider_configs (
    tenant_id TEXT NOT NULL,
    provider_id TEXT NOT NULL,
    display_name TEXT NOT NULL,
    login_url TEXT NOT NULL,
    enabled BIGINT NOT NULL DEFAULT 0 CHECK (enabled IN (0, 1)),
    issuer_url TEXT,
    client_id TEXT,
    secret_ref TEXT,
    scopes_json TEXT NOT NULL DEFAULT '[]',
    redirect_uris_json TEXT NOT NULL DEFAULT '[]',
    claim_mapping_json TEXT NOT NULL DEFAULT '{}',
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (tenant_id, provider_id)
);

CREATE TABLE IF NOT EXISTS auth_redirect_allowlist (
    redirect_uri TEXT PRIMARY KEY,
    created_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_redirect_allowlists (
    tenant_id TEXT PRIMARY KEY,
    redirects_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_signing_keys (
    tenant_id TEXT NOT NULL,
    kid TEXT NOT NULL,
    alg TEXT,
    status TEXT NOT NULL CHECK (status IN ('next', 'active', 'retired', 'revoked')),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    activated_at_ms BIGINT,
    retired_at_ms BIGINT,
    revoked_at_ms BIGINT,
    PRIMARY KEY (tenant_id, kid)
);

CREATE TABLE IF NOT EXISTS auth_jwks (
    kid TEXT PRIMARY KEY,
    kty TEXT NOT NULL,
    alg TEXT NOT NULL,
    use_value TEXT NOT NULL,
    public_parameters_json TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    retired_at_ms BIGINT
);

CREATE TABLE IF NOT EXISTS auth_policy_bundles (
    policy_revision TEXT PRIMARY KEY,
    cedar_schema TEXT NOT NULL,
    cedar_policy TEXT NOT NULL,
    entities_json TEXT NOT NULL,
    checksum TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('staged', 'active', 'retired')),
    created_by_user_id TEXT NOT NULL REFERENCES auth_users(user_id),
    created_at_ms BIGINT NOT NULL,
    activated_at_ms BIGINT
);

CREATE TABLE IF NOT EXISTS auth_idempotency (
    idempotency_key TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    request_hash TEXT NOT NULL,
    response_json TEXT,
    status TEXT NOT NULL CHECK (status IN ('pending', 'committed', 'failed')),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE TABLE IF NOT EXISTS auth_rate_limit_buckets (
    bucket_key TEXT PRIMARY KEY,
    attempt_count BIGINT NOT NULL,
    window_expires_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_rate_limit_expiry_idx
    ON auth_rate_limit_buckets (window_expires_at_ms);

CREATE TABLE IF NOT EXISTS auth_mail_outbox (
    message_id TEXT PRIMARY KEY,
    message_kind TEXT NOT NULL,
    recipient_hash TEXT NOT NULL,
    payload_encrypted TEXT NOT NULL,
    correlation_id TEXT NOT NULL UNIQUE,
    attempt_count BIGINT NOT NULL DEFAULT 0,
    available_at_ms BIGINT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    delivered_at_ms BIGINT,
    delivery_id TEXT,
    last_error_code TEXT,
    lease_id TEXT,
    leased_until_ms BIGINT
);

CREATE INDEX IF NOT EXISTS auth_mail_outbox_pending_idx
    ON auth_mail_outbox (available_at_ms) WHERE delivered_at_ms IS NULL;

CREATE INDEX IF NOT EXISTS idx_auth_mail_outbox_pending
    ON auth_mail_outbox (available_at_ms, delivered_at_ms);

CREATE INDEX IF NOT EXISTS idx_auth_mail_outbox_recipient
    ON auth_mail_outbox (recipient_hash, message_kind, created_at_ms);

CREATE TABLE IF NOT EXISTS auth_relationship_outbox (
    intent_id TEXT PRIMARY KEY,
    operation TEXT NOT NULL,
    resource TEXT NOT NULL,
    relation_name TEXT NOT NULL,
    subject TEXT NOT NULL,
    resource_revision BIGINT NOT NULL,
    consistency_token TEXT,
    status TEXT NOT NULL,
    attempt_count BIGINT NOT NULL DEFAULT 0,
    last_error TEXT,
    available_at_ms BIGINT NOT NULL,
    lease_id TEXT,
    leased_until_ms BIGINT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_relationship_outbox_pending_idx
    ON auth_relationship_outbox (status, available_at_ms);

CREATE INDEX IF NOT EXISTS idx_auth_relationship_outbox_pending
    ON auth_relationship_outbox (status, available_at_ms);

CREATE TABLE IF NOT EXISTS auth_audit_log (
    audit_id TEXT PRIMARY KEY,
    organization_id TEXT REFERENCES auth_organizations(organization_id),
    actor_user_id TEXT REFERENCES auth_users(user_id),
    session_id TEXT,
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied', 'succeeded', 'failed')),
    request_id TEXT NOT NULL,
    policy_revision TEXT,
    metadata_json TEXT NOT NULL DEFAULT '{}',
    occurred_at_ms BIGINT NOT NULL
);

CREATE INDEX IF NOT EXISTS auth_audit_org_cursor_idx
    ON auth_audit_log (organization_id, occurred_at_ms, audit_id);

COMMIT;
