WITH actor AS (
    SELECT sessions.session_id, sessions.user_id
    FROM auth_sessions sessions
    JOIN auth_users users ON users.user_id = sessions.user_id
    JOIN auth_system_administrators administrators
      ON administrators.user_id = users.user_id
     AND administrators.revoked_at_ms IS NULL
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $5
      AND sessions.user_security_revision = users.security_revision
      AND sessions.assurance IN ('aal2', 'aal3')
      AND users.status = 'active'
),
target AS (
    SELECT keys.key_id
    FROM auth_signing_keys keys, actor
    WHERE keys.key_id = $2
      AND keys.status <> 'revoked'
      AND keys.secret_reference IS NOT NULL
    FOR UPDATE OF keys
),
previous AS (
    SELECT keys.key_id
    FROM auth_signing_keys keys, actor
    WHERE keys.status = 'active'
    FOR UPDATE OF keys
),
changed_previous AS (
    UPDATE auth_signing_keys keys
    SET status = CASE WHEN $3 THEN 'retired' ELSE 'next' END,
        retired_at_ms = CASE WHEN $3 THEN $5 ELSE NULL END,
        activated_at_ms = NULL
    FROM target, previous
    WHERE keys.key_id = previous.key_id
      AND keys.key_id <> target.key_id
    RETURNING keys.key_id
),
change_guard AS (
    SELECT count(*) AS changed_count FROM changed_previous
),
activated AS (
    UPDATE auth_signing_keys keys
    SET status = 'active',
        activated_at_ms = $5,
        retired_at_ms = NULL,
        revoked_at_ms = NULL
    FROM target, actor, change_guard
    WHERE keys.key_id = target.key_id
    RETURNING keys.key_id, keys.algorithm, keys.status, keys.created_at_ms, keys.activated_at_ms
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $4::text::uuid, NULL, actor.user_id, actor.session_id,
           'auth.signing-key.activate', 'signing_key', activated.key_id, 'succeeded',
           $6, NULL,
           jsonb_build_object(
               'previous_key_id', (SELECT key_id FROM previous LIMIT 1),
               'retired_previous', $3
           ),
           $5
    FROM actor, activated
    RETURNING audit_id
)
SELECT
    activated.key_id,
    activated.algorithm,
    activated.status,
    activated.created_at_ms,
    activated.activated_at_ms,
    (SELECT key_id FROM previous LIMIT 1) AS previous_key_id
FROM activated
JOIN new_audit ON TRUE
