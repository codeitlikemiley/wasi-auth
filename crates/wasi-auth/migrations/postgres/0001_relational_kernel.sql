CREATE TABLE auth_schema_migrations (
    version TEXT PRIMARY KEY,
    checksum TEXT NOT NULL,
    applied_at_ms BIGINT NOT NULL
);

CREATE TABLE auth_users (
    user_id UUID PRIMARY KEY,
    normalized_email TEXT NOT NULL UNIQUE,
    primary_email TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending_verification', 'active', 'disabled', 'anonymized')),
    security_revision BIGINT NOT NULL DEFAULT 1 CHECK (security_revision > 0),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE TABLE auth_external_identities (
    provider_id TEXT NOT NULL,
    provider_subject TEXT NOT NULL,
    user_id UUID NOT NULL REFERENCES auth_users(user_id) ON DELETE CASCADE,
    email TEXT,
    profile JSONB NOT NULL DEFAULT '{}',
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (provider_id, provider_subject)
);

CREATE TABLE auth_passwords (
    user_id UUID PRIMARY KEY REFERENCES auth_users(user_id) ON DELETE CASCADE,
    password_hash TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    last_authenticated_at_ms BIGINT,
    revoked_at_ms BIGINT
);

CREATE TABLE auth_passkeys (
    credential_id BYTEA PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth_users(user_id) ON DELETE CASCADE,
    public_key_cose BYTEA NOT NULL,
    sign_count BIGINT NOT NULL DEFAULT 0 CHECK (sign_count >= 0),
    transports JSONB NOT NULL DEFAULT '[]',
    display_name TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    last_used_at_ms BIGINT
);

CREATE INDEX auth_passkeys_user_idx ON auth_passkeys (user_id);

CREATE TABLE auth_totp_factors (
    user_id UUID PRIMARY KEY REFERENCES auth_users(user_id) ON DELETE CASCADE,
    key_version TEXT NOT NULL,
    secret_ciphertext BYTEA NOT NULL,
    enabled_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE TABLE auth_recovery_codes (
    user_id UUID NOT NULL REFERENCES auth_users(user_id) ON DELETE CASCADE,
    code_hash BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    used_at_ms BIGINT,
    PRIMARY KEY (user_id, code_hash)
);

CREATE TABLE auth_flows (
    flow_id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('oauth', 'webauthn_registration', 'webauthn_authentication')),
    user_id UUID REFERENCES auth_users(user_id) ON DELETE CASCADE,
    verifier_hash BYTEA NOT NULL UNIQUE,
    key_version TEXT NOT NULL,
    payload_ciphertext BYTEA NOT NULL,
    expires_at_ms BIGINT NOT NULL,
    consumed_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL
);

CREATE INDEX auth_flows_expiry_idx ON auth_flows (expires_at_ms) WHERE consumed_at_ms IS NULL;

CREATE TABLE auth_sessions (
    session_id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES auth_users(user_id) ON DELETE CASCADE,
    selected_organization_id UUID,
    assurance TEXT NOT NULL CHECK (assurance IN ('aal1', 'aal2', 'aal3')),
    session_revision BIGINT NOT NULL DEFAULT 1 CHECK (session_revision > 0),
    user_security_revision BIGINT NOT NULL CHECK (user_security_revision > 0),
    expires_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE INDEX auth_sessions_user_idx ON auth_sessions (user_id, revoked_at_ms, expires_at_ms);

CREATE TABLE auth_refresh_tokens (
    token_hash BYTEA PRIMARY KEY,
    session_id UUID NOT NULL REFERENCES auth_sessions(session_id) ON DELETE CASCADE,
    family_id UUID NOT NULL,
    successor_hash BYTEA,
    successor_key_version TEXT,
    successor_ciphertext BYTEA,
    replay_until_ms BIGINT,
    expires_at_ms BIGINT NOT NULL,
    rotated_at_ms BIGINT,
    revoked_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL
);

CREATE INDEX auth_refresh_family_idx ON auth_refresh_tokens (family_id, revoked_at_ms);

CREATE TABLE auth_one_time_tokens (
    token_hash BYTEA PRIMARY KEY,
    purpose TEXT NOT NULL CHECK (purpose IN ('email_verification', 'password_reset', 'invitation')),
    user_id UUID REFERENCES auth_users(user_id) ON DELETE CASCADE,
    subject_hint TEXT,
    redirect_uri TEXT,
    payload JSONB NOT NULL DEFAULT '{}',
    expires_at_ms BIGINT NOT NULL,
    consumed_at_ms BIGINT,
    created_at_ms BIGINT NOT NULL
);

CREATE INDEX auth_one_time_tokens_expiry_idx
    ON auth_one_time_tokens (purpose, expires_at_ms) WHERE consumed_at_ms IS NULL;

CREATE TABLE auth_organizations (
    organization_id UUID PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'archived')),
    authorization_revision BIGINT NOT NULL DEFAULT 1 CHECK (authorization_revision > 0),
    created_by UUID NOT NULL REFERENCES auth_users(user_id),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

ALTER TABLE auth_sessions
    ADD CONSTRAINT auth_sessions_selected_org_fk
    FOREIGN KEY (selected_organization_id) REFERENCES auth_organizations(organization_id);

CREATE TABLE auth_roles (
    organization_id UUID NOT NULL REFERENCES auth_organizations(organization_id) ON DELETE CASCADE,
    role_id TEXT NOT NULL,
    name TEXT NOT NULL,
    built_in BOOLEAN NOT NULL DEFAULT FALSE,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (organization_id, role_id),
    UNIQUE (organization_id, name)
);

CREATE TABLE auth_role_permissions (
    organization_id UUID NOT NULL,
    role_id TEXT NOT NULL,
    permission TEXT NOT NULL,
    PRIMARY KEY (organization_id, role_id, permission),
    FOREIGN KEY (organization_id, role_id)
        REFERENCES auth_roles(organization_id, role_id) ON DELETE CASCADE
);

CREATE TABLE auth_memberships (
    organization_id UUID NOT NULL REFERENCES auth_organizations(organization_id) ON DELETE CASCADE,
    user_id UUID NOT NULL REFERENCES auth_users(user_id) ON DELETE CASCADE,
    role_id TEXT NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('active', 'suspended', 'blocked', 'removed')),
    joined_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    PRIMARY KEY (organization_id, user_id),
    FOREIGN KEY (organization_id, role_id)
        REFERENCES auth_roles(organization_id, role_id)
);

CREATE INDEX auth_memberships_user_idx ON auth_memberships (user_id, status);

CREATE TABLE auth_invitations (
    invitation_id UUID PRIMARY KEY,
    organization_id UUID NOT NULL REFERENCES auth_organizations(organization_id) ON DELETE CASCADE,
    normalized_email TEXT NOT NULL,
    role_id TEXT NOT NULL,
    token_hash BYTEA NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('pending', 'accepted', 'revoked', 'expired')),
    expires_at_ms BIGINT NOT NULL,
    accepted_at_ms BIGINT,
    created_by UUID NOT NULL REFERENCES auth_users(user_id),
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL,
    FOREIGN KEY (organization_id, role_id)
        REFERENCES auth_roles(organization_id, role_id)
);

CREATE INDEX auth_invitations_org_idx ON auth_invitations (organization_id, status);

CREATE TABLE auth_system_administrators (
    user_id UUID PRIMARY KEY REFERENCES auth_users(user_id) ON DELETE CASCADE,
    granted_by UUID REFERENCES auth_users(user_id),
    granted_at_ms BIGINT NOT NULL,
    revoked_at_ms BIGINT
);

CREATE TABLE auth_provider_configs (
    provider_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    enabled BOOLEAN NOT NULL DEFAULT FALSE,
    secret_reference TEXT,
    scopes JSONB NOT NULL DEFAULT '[]',
    claim_mapping JSONB NOT NULL DEFAULT '{}',
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE TABLE auth_redirect_uris (
    provider_id TEXT NOT NULL REFERENCES auth_provider_configs(provider_id) ON DELETE CASCADE,
    redirect_uri TEXT NOT NULL,
    created_at_ms BIGINT NOT NULL,
    PRIMARY KEY (provider_id, redirect_uri)
);

CREATE TABLE auth_signing_keys (
    key_id TEXT PRIMARY KEY,
    algorithm TEXT NOT NULL CHECK (algorithm = 'ES256'),
    status TEXT NOT NULL CHECK (status IN ('next', 'active', 'retired', 'revoked')),
    public_jwk JSONB NOT NULL,
    key_version TEXT NOT NULL,
    private_key_ciphertext BYTEA NOT NULL,
    created_at_ms BIGINT NOT NULL,
    activated_at_ms BIGINT,
    retired_at_ms BIGINT,
    revoked_at_ms BIGINT
);

CREATE UNIQUE INDEX auth_one_active_signing_key_idx
    ON auth_signing_keys (status) WHERE status = 'active';

CREATE TABLE auth_policy_bundles (
    policy_revision TEXT PRIMARY KEY,
    cedar_schema TEXT NOT NULL,
    cedar_policy TEXT NOT NULL,
    entities JSONB NOT NULL,
    checksum BYTEA NOT NULL UNIQUE,
    status TEXT NOT NULL CHECK (status IN ('staged', 'active', 'retired')),
    created_by UUID NOT NULL REFERENCES auth_users(user_id),
    created_at_ms BIGINT NOT NULL,
    activated_at_ms BIGINT
);

CREATE UNIQUE INDEX auth_one_active_policy_idx
    ON auth_policy_bundles (status) WHERE status = 'active';

CREATE TABLE auth_idempotency (
    idempotency_key TEXT PRIMARY KEY,
    actor_key TEXT NOT NULL,
    operation TEXT NOT NULL,
    request_hash BYTEA NOT NULL,
    response_public JSONB,
    response_key_version TEXT,
    response_ciphertext BYTEA,
    expires_at_ms BIGINT NOT NULL,
    committed_at_ms BIGINT NOT NULL
);

CREATE INDEX auth_idempotency_expiry_idx ON auth_idempotency (expires_at_ms);

CREATE TABLE auth_rate_limit_buckets (
    bucket_key TEXT PRIMARY KEY,
    attempt_count BIGINT NOT NULL CHECK (attempt_count >= 0),
    window_expires_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE INDEX auth_rate_limit_expiry_idx ON auth_rate_limit_buckets (window_expires_at_ms);

CREATE TABLE auth_outbox (
    outbox_id UUID PRIMARY KEY,
    kind TEXT NOT NULL CHECK (kind IN ('mail', 'relationship')),
    deduplication_key TEXT NOT NULL UNIQUE,
    key_version TEXT NOT NULL,
    payload_ciphertext BYTEA NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'leased', 'delivered', 'dead_letter')),
    attempt_count BIGINT NOT NULL DEFAULT 0 CHECK (attempt_count >= 0),
    available_at_ms BIGINT NOT NULL,
    lease_id UUID,
    leased_until_ms BIGINT,
    delivered_at_ms BIGINT,
    last_error_code TEXT,
    created_at_ms BIGINT NOT NULL,
    updated_at_ms BIGINT NOT NULL
);

CREATE INDEX auth_outbox_pending_idx ON auth_outbox (status, available_at_ms);

CREATE TABLE auth_audit_log (
    audit_id UUID PRIMARY KEY,
    organization_id UUID REFERENCES auth_organizations(organization_id),
    actor_user_id UUID REFERENCES auth_users(user_id),
    session_id UUID REFERENCES auth_sessions(session_id),
    action TEXT NOT NULL,
    resource_type TEXT NOT NULL,
    resource_id TEXT NOT NULL,
    outcome TEXT NOT NULL CHECK (outcome IN ('allowed', 'denied', 'succeeded', 'failed')),
    request_id TEXT NOT NULL,
    policy_revision TEXT,
    metadata JSONB NOT NULL DEFAULT '{}',
    occurred_at_ms BIGINT NOT NULL
);

CREATE INDEX auth_audit_cursor_idx ON auth_audit_log (occurred_at_ms, audit_id);
CREATE INDEX auth_audit_org_cursor_idx
    ON auth_audit_log (organization_id, occurred_at_ms, audit_id);
