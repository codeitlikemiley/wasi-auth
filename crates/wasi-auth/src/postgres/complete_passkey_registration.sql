WITH valid_session AS (
    SELECT sessions.session_id, sessions.user_id
    FROM auth_sessions sessions
    JOIN auth_users users ON users.user_id = sessions.user_id
    WHERE sessions.session_id = $3::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $8
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
    FOR UPDATE OF sessions
),
consumed_flow AS (
    UPDATE auth_flows flows
    SET consumed_at_ms = $8
    FROM valid_session
    WHERE flows.flow_id = $2::text::uuid
      AND flows.verifier_hash = $1
      AND flows.kind = 'webauthn_registration'
      AND flows.user_id = valid_session.user_id
      AND flows.consumed_at_ms IS NULL
      AND flows.expires_at_ms >= $8
    RETURNING flows.flow_id, valid_session.session_id, valid_session.user_id
),
new_credential AS (
    INSERT INTO auth_passkeys (
        credential_id, user_id, public_key_cose, sign_count,
        transports, display_name, created_at_ms, last_used_at_ms
    )
    SELECT $4, consumed_flow.user_id, $5, $6, $7, $9, $8, NULL
    FROM consumed_flow
    ON CONFLICT (credential_id) DO NOTHING
    RETURNING credential_id, user_id
),
elevated_session AS (
    UPDATE auth_sessions sessions
    SET assurance = 'aal2',
        session_revision = session_revision + 1,
        updated_at_ms = $8
    FROM consumed_flow, new_credential
    WHERE sessions.session_id = consumed_flow.session_id
      AND new_credential.user_id = sessions.user_id
    RETURNING sessions.session_id, sessions.user_id, sessions.expires_at_ms
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $10::text::uuid, NULL, elevated_session.user_id, elevated_session.session_id,
           'auth.passkey.register', 'passkey', encode($4, 'base64'), 'succeeded',
           $11, NULL, '{"assurance":"aal2"}'::jsonb, $8
    FROM elevated_session
    RETURNING audit_id
)
SELECT
    'registered'::text AS outcome,
    elevated_session.session_id::text AS session_id,
    elevated_session.user_id::text AS user_id,
    users.primary_email,
    elevated_session.expires_at_ms
FROM elevated_session
JOIN auth_users users ON users.user_id = elevated_session.user_id
JOIN new_audit ON TRUE
UNION ALL
SELECT
    'credential_conflict'::text AS outcome,
    NULL::text AS session_id,
    NULL::text AS user_id,
    NULL::text AS primary_email,
    NULL::bigint AS expires_at_ms
FROM consumed_flow
WHERE NOT EXISTS (SELECT 1 FROM new_credential)
LIMIT 1
