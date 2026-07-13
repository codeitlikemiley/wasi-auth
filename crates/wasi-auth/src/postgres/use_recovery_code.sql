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
used_code AS (
    UPDATE auth_recovery_codes AS recovery
    SET used_at_ms = $3
    FROM actor
    WHERE recovery.user_id = actor.user_id
      AND recovery.code_hash = $2
      AND recovery.used_at_ms IS NULL
    RETURNING recovery.user_id
),
elevated AS (
    UPDATE auth_sessions AS sessions
    SET assurance = 'aal2',
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $3
    FROM actor JOIN used_code ON used_code.user_id = actor.user_id
    WHERE sessions.session_id = actor.session_id
    RETURNING sessions.session_id, sessions.user_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, actor_user_id, session_id, action, resource_type,
        resource_id, outcome, request_id, metadata, occurred_at_ms
    )
    SELECT $4::text::uuid, elevated.user_id, elevated.session_id,
           'auth.mfa.recovery.verify', 'session', elevated.session_id::text,
           'succeeded', $5, '{}', $3
    FROM elevated
    RETURNING audit_id
)
SELECT 'elevated'::text AS outcome
FROM new_audit
