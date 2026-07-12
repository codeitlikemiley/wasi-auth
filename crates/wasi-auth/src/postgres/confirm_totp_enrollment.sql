WITH actor AS (
    SELECT sessions.session_id, sessions.user_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $3::bigint
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
    FOR UPDATE OF sessions
),
enabled_factor AS (
    UPDATE auth_totp_factors AS factors
    SET enabled_at_ms = $3, updated_at_ms = $3
    FROM actor
    WHERE factors.user_id = actor.user_id
      AND factors.secret_ciphertext = $2
      AND factors.enabled_at_ms IS NULL
    RETURNING factors.user_id
),
deleted_recovery AS (
    DELETE FROM auth_recovery_codes AS recovery
    USING enabled_factor
    WHERE recovery.user_id = enabled_factor.user_id
    RETURNING recovery.code_hash
),
delete_barrier AS (
    SELECT count(*) AS deleted FROM deleted_recovery
),
new_recovery AS (
    INSERT INTO auth_recovery_codes (user_id, code_hash, created_at_ms)
    SELECT enabled_factor.user_id, decode(codes.code, 'hex'), $3
    FROM enabled_factor
    CROSS JOIN delete_barrier
    CROSS JOIN LATERAL jsonb_array_elements_text($4::jsonb) AS codes(code)
    RETURNING user_id
),
recovery_barrier AS (
    SELECT count(*) AS inserted FROM new_recovery
),
elevated_session AS (
    UPDATE auth_sessions AS sessions
    SET assurance = 'aal2',
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $3
    FROM actor CROSS JOIN recovery_barrier
    WHERE sessions.session_id = actor.session_id
    RETURNING sessions.session_id, sessions.user_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, actor_user_id, session_id, action, resource_type,
        resource_id, outcome, request_id, metadata, occurred_at_ms
    )
    SELECT $5::text::uuid, elevated_session.user_id, elevated_session.session_id,
           'auth.mfa.totp.confirm', 'user', elevated_session.user_id::text,
           'succeeded', $6,
           jsonb_build_object('recovery_codes', (SELECT inserted FROM recovery_barrier)), $3
    FROM elevated_session
    RETURNING audit_id
)
SELECT 'confirmed'::text AS outcome
FROM new_audit
