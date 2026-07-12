WITH eligible AS (
    SELECT users.user_id, users.security_revision
    FROM auth_users AS users
    JOIN auth_passwords AS passwords ON passwords.user_id = users.user_id
    WHERE users.user_id = $1::text::uuid
      AND users.normalized_email = $2
      AND users.status = 'active'
      AND passwords.revoked_at_ms IS NULL
      AND passwords.password_hash = $3
    FOR UPDATE OF users, passwords
),
password_used AS (
    UPDATE auth_passwords AS passwords
    SET last_authenticated_at_ms = $6, updated_at_ms = $6
    FROM eligible
    WHERE passwords.user_id = eligible.user_id
    RETURNING passwords.user_id
),
new_session AS (
    INSERT INTO auth_sessions (
        session_id, user_id, selected_organization_id, assurance,
        session_revision, user_security_revision, expires_at_ms,
        revoked_at_ms, created_at_ms, updated_at_ms
    )
    SELECT $4::text::uuid, eligible.user_id, NULL, 'aal1',
           1, eligible.security_revision, $5, NULL, $6, $6
    FROM eligible
    JOIN password_used ON password_used.user_id = eligible.user_id
    RETURNING session_id, user_id, expires_at_ms
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $7::text::uuid, NULL, new_session.user_id, new_session.session_id,
           'auth.password.login', 'session', new_session.session_id::text, 'succeeded',
           $8, NULL, '{"channel":"password"}'::jsonb, $6
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
