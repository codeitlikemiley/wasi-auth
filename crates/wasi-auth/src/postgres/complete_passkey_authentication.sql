WITH consumed_flow AS (
    UPDATE auth_flows
    SET consumed_at_ms = $12
    WHERE flow_id = $2::text::uuid
      AND verifier_hash = $1
      AND kind = 'webauthn_authentication'
      AND user_id = $3::text::uuid
      AND consumed_at_ms IS NULL
      AND expires_at_ms >= $12
    RETURNING flow_id, user_id
),
updated_credential AS (
    UPDATE auth_passkeys passkeys
    SET public_key_cose = $5,
        sign_count = $7,
        transports = $8,
        last_used_at_ms = $12
    FROM consumed_flow
    WHERE passkeys.user_id = consumed_flow.user_id
      AND passkeys.credential_id = $4
      AND passkeys.sign_count = $6
    RETURNING passkeys.user_id
),
new_session AS (
    INSERT INTO auth_sessions (
        session_id, user_id, selected_organization_id, assurance,
        session_revision, user_security_revision, expires_at_ms,
        revoked_at_ms, created_at_ms, updated_at_ms
    )
    SELECT $9::text::uuid, users.user_id, NULL, 'aal2',
           1, users.security_revision, $10, NULL, $12, $12
    FROM updated_credential
    JOIN auth_users users ON users.user_id = updated_credential.user_id
    WHERE users.status = 'active'
    RETURNING session_id, user_id, expires_at_ms
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $11::text::uuid, NULL, new_session.user_id, new_session.session_id,
           'auth.passkey.login', 'session', new_session.session_id::text, 'succeeded',
           $13, NULL, '{"assurance":"aal2"}'::jsonb, $12
    FROM new_session
    RETURNING audit_id
)
SELECT
    'authenticated'::text AS outcome,
    new_session.session_id::text AS session_id,
    new_session.user_id::text AS user_id,
    users.primary_email,
    new_session.expires_at_ms
FROM new_session
JOIN auth_users users ON users.user_id = new_session.user_id
JOIN new_audit ON TRUE
UNION ALL
SELECT
    'counter_conflict'::text AS outcome,
    NULL::text AS session_id,
    NULL::text AS user_id,
    NULL::text AS primary_email,
    NULL::bigint AS expires_at_ms
FROM consumed_flow
WHERE NOT EXISTS (SELECT 1 FROM updated_credential)
LIMIT 1
