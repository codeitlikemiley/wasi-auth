WITH actor AS (
    SELECT sessions.session_id, sessions.user_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $4::bigint
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
    FOR UPDATE OF sessions, users
),
saved_factor AS (
    INSERT INTO auth_totp_factors (
        user_id, key_version, secret_ciphertext,
        enabled_at_ms, created_at_ms, updated_at_ms
    )
    SELECT actor.user_id, $2, $3, NULL, $4, $4
    FROM actor
    ON CONFLICT (user_id) DO UPDATE
    SET key_version = EXCLUDED.key_version,
        secret_ciphertext = EXCLUDED.secret_ciphertext,
        updated_at_ms = EXCLUDED.updated_at_ms
    WHERE auth_totp_factors.enabled_at_ms IS NULL
    RETURNING user_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, actor_user_id, session_id, action, resource_type,
        resource_id, outcome, request_id, metadata, occurred_at_ms
    )
    SELECT $5::text::uuid, actor.user_id, actor.session_id,
           'auth.mfa.totp.start', 'user', actor.user_id::text,
           'succeeded', $6, '{}', $4
    FROM actor JOIN saved_factor ON TRUE
    RETURNING audit_id
)
SELECT 'started'::text AS outcome
FROM new_audit
