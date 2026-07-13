WITH token_candidate AS MATERIALIZED (
    SELECT token_hash, user_id
    FROM auth_one_time_tokens
    WHERE token_hash = $1
      AND purpose = 'password_reset'
      AND expires_at_ms >= $2
      AND consumed_at_ms IS NULL
    FOR UPDATE
),
consumed AS (
    UPDATE auth_one_time_tokens AS tokens
    SET consumed_at_ms = $2
    FROM token_candidate
    WHERE tokens.token_hash = token_candidate.token_hash
    RETURNING tokens.user_id
),
updated_password AS (
    UPDATE auth_passwords AS passwords
    SET password_hash = $3,
        revoked_at_ms = NULL,
        updated_at_ms = $2
    FROM consumed
    WHERE passwords.user_id = consumed.user_id
    RETURNING passwords.user_id
),
secured_user AS (
    UPDATE auth_users AS users
    SET security_revision = users.security_revision + 1,
        updated_at_ms = $2
    FROM updated_password
    WHERE users.user_id = updated_password.user_id
      AND users.status = 'active'
    RETURNING users.user_id, users.security_revision
),
revoked_sessions AS (
    UPDATE auth_sessions AS sessions
    SET revoked_at_ms = $2, updated_at_ms = $2
    FROM secured_user
    WHERE sessions.user_id = secured_user.user_id
      AND sessions.revoked_at_ms IS NULL
    RETURNING sessions.session_id
),
revoked_refresh_tokens AS (
    UPDATE auth_refresh_tokens AS refresh_tokens
    SET revoked_at_ms = $2
    WHERE refresh_tokens.session_id IN (
        SELECT sessions.session_id
        FROM auth_sessions AS sessions
        JOIN secured_user ON secured_user.user_id = sessions.user_id
    )
      AND refresh_tokens.revoked_at_ms IS NULL
    RETURNING refresh_tokens.token_hash
),
new_session AS (
    INSERT INTO auth_sessions (
        session_id, user_id, selected_organization_id, assurance,
        session_revision, user_security_revision, expires_at_ms,
        revoked_at_ms, created_at_ms, updated_at_ms
    )
    SELECT $4::text::uuid, secured_user.user_id, NULL, 'aal1',
           1, secured_user.security_revision, $5, NULL, $2, $2
    FROM secured_user
    RETURNING session_id, user_id, expires_at_ms
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $6::text::uuid, NULL, new_session.user_id, new_session.session_id,
           'auth.password.reset.complete', 'user', new_session.user_id::text, 'succeeded',
           $7, NULL, '{}', $2
    FROM new_session
    RETURNING audit_id
)
SELECT
    'created'::text AS outcome,
    new_session.session_id::text AS session_id,
    new_session.user_id::text AS user_id,
    new_session.expires_at_ms
FROM new_session
JOIN new_audit ON TRUE
LIMIT 1
