WITH actor AS (
    SELECT sessions.session_id, sessions.user_id
    FROM auth_sessions sessions
    JOIN auth_users users ON users.user_id = sessions.user_id
    JOIN auth_system_administrators administrators
      ON administrators.user_id = users.user_id
     AND administrators.revoked_at_ms IS NULL
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $7
      AND sessions.user_security_revision = users.security_revision
      AND sessions.assurance IN ('aal2', 'aal3')
      AND users.status = 'active'
),
retired AS (
    UPDATE auth_policy_bundles bundles
    SET status = 'retired'
    FROM actor
    WHERE bundles.status = 'active'
      AND bundles.checksum <> $6
    RETURNING bundles.policy_revision
),
published AS (
    INSERT INTO auth_policy_bundles (
        policy_revision, cedar_schema, cedar_policy, entities,
        checksum, status, created_by, created_at_ms, activated_at_ms
    )
    SELECT $2, $3, $4, $5, $6, 'active', actor.user_id, $7, $7
    FROM actor
    ON CONFLICT (checksum) DO UPDATE
    SET status = 'active',
        activated_at_ms = EXCLUDED.activated_at_ms
    RETURNING
        policy_revision,
        encode(checksum, 'hex') AS checksum_hex,
        status,
        created_by::text AS created_by,
        created_at_ms,
        activated_at_ms
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $8::text::uuid, NULL, actor.user_id, actor.session_id,
           'auth.policy.publish', 'policy_bundle', published.policy_revision, 'succeeded',
           $9, published.policy_revision,
           jsonb_build_object('retired_count', (SELECT count(*) FROM retired)), $7
    FROM actor, published
    RETURNING audit_id
)
SELECT published.*
FROM published
JOIN new_audit ON TRUE
