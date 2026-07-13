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
saved AS (
    INSERT INTO auth_provider_configs (
        provider_id, display_name, enabled, secret_reference,
        scopes, claim_mapping, created_at_ms, updated_at_ms
    )
    SELECT $2, $3, $4, NULL, '[]'::jsonb, '{}'::jsonb, $5, $5
    FROM actor
    ON CONFLICT (provider_id) DO UPDATE
    SET display_name = EXCLUDED.display_name,
        enabled = EXCLUDED.enabled,
        updated_at_ms = EXCLUDED.updated_at_ms
    RETURNING provider_id, display_name, enabled, scopes, claim_mapping
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $6::text::uuid, NULL, actor.user_id, actor.session_id,
           'auth.provider.update', 'oauth_provider', saved.provider_id, 'succeeded',
           $7, NULL, jsonb_build_object('enabled', saved.enabled), $5
    FROM actor, saved
    RETURNING audit_id
)
SELECT
    saved.provider_id,
    saved.display_name,
    saved.enabled,
    saved.scopes,
    saved.claim_mapping
FROM saved
JOIN new_audit ON TRUE
