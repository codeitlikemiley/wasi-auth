WITH eligible AS (
    SELECT sessions.session_id, sessions.user_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $5::bigint
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
    FOR UPDATE OF sessions
),
new_token AS (
    INSERT INTO auth_refresh_tokens (
        token_hash, session_id, family_id, expires_at_ms, created_at_ms
    )
    SELECT $2, eligible.session_id, $3::text::uuid, $4, $5
    FROM eligible
    ON CONFLICT (token_hash) DO NOTHING
    RETURNING session_id, family_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, actor_user_id, session_id, action, resource_type,
        resource_id, outcome, request_id, metadata, occurred_at_ms
    )
    SELECT $6::text::uuid, eligible.user_id, new_token.session_id,
           'auth.token.issue', 'session', new_token.session_id::text,
           'succeeded', $7,
           jsonb_build_object('family_id', new_token.family_id::text), $5
    FROM new_token JOIN eligible ON TRUE
    RETURNING audit_id
)
SELECT 'issued'::text AS outcome
FROM new_audit
