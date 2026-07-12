WITH token_candidate AS MATERIALIZED (
    SELECT token_hash, user_id, consumed_at_ms, payload
    FROM auth_one_time_tokens
    WHERE token_hash = $1
      AND purpose = 'email_verification'
      AND expires_at_ms >= $2
    FOR UPDATE
),
replayed AS (
    SELECT sessions.session_id, sessions.user_id, sessions.expires_at_ms
    FROM token_candidate
    JOIN auth_sessions AS sessions
      ON sessions.session_id = NULLIF(token_candidate.payload->>'result_session_id', '')::uuid
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    WHERE token_candidate.consumed_at_ms IS NOT NULL
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $2
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
),
consumed AS (
    UPDATE auth_one_time_tokens AS tokens
    SET consumed_at_ms = $2,
        payload = jsonb_set(tokens.payload, '{result_session_id}', to_jsonb($3::text), TRUE)
    FROM token_candidate
    WHERE tokens.token_hash = token_candidate.token_hash
      AND token_candidate.consumed_at_ms IS NULL
    RETURNING tokens.user_id
),
activated AS (
    UPDATE auth_users AS users
    SET status = 'active', updated_at_ms = $2
    FROM consumed
    WHERE users.user_id = consumed.user_id
      AND users.status IN ('pending_verification', 'active')
    RETURNING users.user_id, users.security_revision
),
new_session AS (
    INSERT INTO auth_sessions (
        session_id, user_id, selected_organization_id, assurance,
        session_revision, user_security_revision, expires_at_ms,
        revoked_at_ms, created_at_ms, updated_at_ms
    )
    SELECT $3::text::uuid, activated.user_id, NULL, 'aal1',
           1, activated.security_revision, $4, NULL, $2, $2
    FROM activated
    RETURNING session_id, user_id, expires_at_ms
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $5::text::uuid, NULL, new_session.user_id, new_session.session_id,
           'auth.email.verify', 'user', new_session.user_id::text, 'succeeded',
           $6, NULL, '{}', $2
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
UNION ALL
SELECT
    'replayed'::text AS outcome,
    replayed.session_id::text AS session_id,
    replayed.user_id::text AS user_id,
    replayed.expires_at_ms
FROM replayed
LIMIT 1
