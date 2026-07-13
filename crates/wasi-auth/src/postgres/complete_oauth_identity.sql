WITH consumed_flow AS (
    UPDATE auth_flows
    SET consumed_at_ms = $11
    WHERE flow_id = $2::text::uuid
      AND verifier_hash = $1
      AND kind = 'oauth'
      AND consumed_at_ms IS NULL
      AND expires_at_ms >= $11
    RETURNING flow_id
),
existing_identity AS (
    SELECT identity.user_id, users.status, users.security_revision, users.primary_email
    FROM auth_external_identities identity
    JOIN auth_users users ON users.user_id = identity.user_id
    JOIN consumed_flow ON TRUE
    WHERE identity.provider_id = $3
      AND identity.provider_subject = $4
),
resolved_user AS (
    INSERT INTO auth_users (
        user_id, normalized_email, primary_email, status,
        security_revision, created_at_ms, updated_at_ms
    )
    SELECT $8::text::uuid, $5, $6, 'active', 1, $11, $11
    FROM consumed_flow
    WHERE NOT EXISTS (SELECT 1 FROM existing_identity)
      AND $5::text IS NOT NULL
      AND $6::text IS NOT NULL
    ON CONFLICT (normalized_email) DO UPDATE
    SET updated_at_ms = auth_users.updated_at_ms
    RETURNING user_id, status, security_revision, primary_email
),
selected_user AS (
    SELECT user_id, status, security_revision, primary_email FROM existing_identity
    UNION ALL
    SELECT user_id, status, security_revision, primary_email FROM resolved_user
    WHERE NOT EXISTS (SELECT 1 FROM existing_identity)
    LIMIT 1
),
linked_identity AS (
    INSERT INTO auth_external_identities (
        provider_id, provider_subject, user_id, email, profile,
        created_at_ms, updated_at_ms
    )
    SELECT $3, $4, selected_user.user_id, $6, $7, $11, $11
    FROM selected_user
    ON CONFLICT (provider_id, provider_subject) DO UPDATE
    SET email = EXCLUDED.email,
        profile = EXCLUDED.profile,
        updated_at_ms = EXCLUDED.updated_at_ms
    WHERE auth_external_identities.user_id = EXCLUDED.user_id
    RETURNING user_id
),
new_session AS (
    INSERT INTO auth_sessions (
        session_id, user_id, selected_organization_id, assurance,
        session_revision, user_security_revision, expires_at_ms,
        revoked_at_ms, created_at_ms, updated_at_ms
    )
    SELECT $9::text::uuid, selected_user.user_id, NULL, 'aal1',
           1, selected_user.security_revision, $10, NULL, $11, $11
    FROM linked_identity
    JOIN selected_user ON selected_user.user_id = linked_identity.user_id
    WHERE selected_user.status = 'active'
    RETURNING session_id, user_id, expires_at_ms
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $12::text::uuid, NULL, new_session.user_id, new_session.session_id,
           'auth.oauth.login', 'session', new_session.session_id::text, 'succeeded',
           $13, NULL, jsonb_build_object('provider_id', $3), $11
    FROM new_session
    RETURNING audit_id
)
SELECT
    'completed'::text AS outcome,
    new_session.session_id::text AS session_id,
    new_session.user_id::text AS user_id,
    selected_user.primary_email,
    new_session.expires_at_ms
FROM new_session
JOIN selected_user ON selected_user.user_id = new_session.user_id
JOIN new_audit ON TRUE
UNION ALL
SELECT
    'account_unavailable'::text AS outcome,
    NULL::text AS session_id,
    NULL::text AS user_id,
    NULL::text AS primary_email,
    NULL::bigint AS expires_at_ms
FROM consumed_flow
WHERE NOT EXISTS (SELECT 1 FROM new_session)
LIMIT 1
