WITH actor AS (
    SELECT actor_session.session_id, actor_session.user_id
    FROM auth_sessions AS actor_session
    JOIN auth_users AS users ON users.user_id = actor_session.user_id
    WHERE actor_session.session_id = $2::text::uuid
      AND actor_session.revoked_at_ms IS NULL
      AND actor_session.expires_at_ms > $3
      AND actor_session.user_security_revision = users.security_revision
      AND users.status = 'active'
),
revoked_session AS (
    UPDATE auth_sessions AS target
    SET revoked_at_ms = $3,
        session_revision = target.session_revision + 1,
        updated_at_ms = $3
    FROM actor
    WHERE target.session_id = $1::text::uuid
      AND target.user_id = actor.user_id
      AND target.revoked_at_ms IS NULL
    RETURNING target.session_id, target.user_id
),
revoked_refresh_tokens AS (
    UPDATE auth_refresh_tokens AS refresh_tokens
    SET revoked_at_ms = $3
    FROM revoked_session
    WHERE refresh_tokens.session_id = revoked_session.session_id
      AND refresh_tokens.revoked_at_ms IS NULL
    RETURNING refresh_tokens.token_hash
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $4::text::uuid, NULL, revoked_session.user_id, actor.session_id,
           'auth.session.revoke', 'session', revoked_session.session_id::text, 'succeeded',
           $5, NULL, '{}', $3
    FROM revoked_session
    JOIN actor ON TRUE
    RETURNING audit_id
)
SELECT 'revoked'::text AS outcome
FROM new_audit
