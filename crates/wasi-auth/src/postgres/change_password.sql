WITH eligible AS (
    SELECT sessions.session_id, sessions.user_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    WHERE sessions.session_id = $2::text::uuid
      AND sessions.user_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $5
      AND sessions.user_security_revision = users.security_revision
      -- AAL1 is allowed: current-password verification is the re-auth step.
      -- AAL2/AAL3 also work after MFA step-up.
      AND sessions.assurance IN ('aal1', 'aal2', 'aal3')
      AND users.status = 'active'
    FOR UPDATE OF sessions, users
),
updated_password AS (
    UPDATE auth_passwords AS passwords
    SET password_hash = $4, updated_at_ms = $5
    FROM eligible
    WHERE passwords.user_id = eligible.user_id
      AND passwords.password_hash = $3
      AND passwords.revoked_at_ms IS NULL
    RETURNING passwords.user_id
),
secured_user AS (
    UPDATE auth_users AS users
    SET security_revision = users.security_revision + 1,
        updated_at_ms = $5
    FROM updated_password
    WHERE users.user_id = updated_password.user_id
    RETURNING users.user_id, users.security_revision
),
current_session AS (
    UPDATE auth_sessions AS sessions
    SET user_security_revision = secured_user.security_revision,
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $5
    FROM secured_user
    WHERE sessions.session_id = $2::text::uuid
      AND sessions.user_id = secured_user.user_id
    RETURNING sessions.session_id, sessions.user_id
),
revoked_other_sessions AS (
    UPDATE auth_sessions AS sessions
    SET revoked_at_ms = $5,
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $5
    FROM secured_user
    WHERE sessions.user_id = secured_user.user_id
      AND sessions.session_id <> $2::text::uuid
      AND sessions.revoked_at_ms IS NULL
    RETURNING sessions.session_id
),
revoked_refresh_tokens AS (
    UPDATE auth_refresh_tokens AS refresh_tokens
    SET revoked_at_ms = $5
    WHERE refresh_tokens.session_id <> $2::text::uuid
      AND refresh_tokens.session_id IN (
          SELECT sessions.session_id
          FROM auth_sessions AS sessions
          JOIN secured_user ON secured_user.user_id = sessions.user_id
      )
      AND refresh_tokens.revoked_at_ms IS NULL
    RETURNING refresh_tokens.token_hash
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $6::text::uuid, NULL, current_session.user_id, current_session.session_id,
           'auth.password.change', 'user', current_session.user_id::text, 'succeeded',
           $7, NULL, '{}', $5
    FROM current_session
    RETURNING audit_id
)
SELECT 'changed'::text AS outcome
FROM new_audit
