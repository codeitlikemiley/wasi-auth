WITH actor AS (
    SELECT sessions.session_id, sessions.user_id
    FROM auth_sessions sessions
    JOIN auth_users users ON users.user_id = sessions.user_id
    JOIN auth_system_administrators administrators
      ON administrators.user_id = users.user_id
     AND administrators.revoked_at_ms IS NULL
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $3
      AND sessions.user_security_revision = users.security_revision
      AND sessions.assurance IN ('aal2', 'aal3')
      AND users.status = 'active'
),
desired AS (
    SELECT DISTINCT value AS redirect_path
    FROM actor, jsonb_array_elements_text($2) AS value
),
inserted AS (
    INSERT INTO auth_application_redirects (redirect_path, created_at_ms)
    SELECT redirect_path, $3
    FROM desired
    ON CONFLICT (redirect_path) DO UPDATE
    SET created_at_ms = auth_application_redirects.created_at_ms
    RETURNING redirect_path
),
removed AS (
    DELETE FROM auth_application_redirects redirects
    USING actor
    WHERE NOT EXISTS (
        SELECT 1 FROM desired
        WHERE desired.redirect_path = redirects.redirect_path
    )
    RETURNING redirects.redirect_path
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $4::text::uuid, NULL, actor.user_id, actor.session_id,
           'auth.redirect-allowlist.replace', 'redirect_allowlist', 'application', 'succeeded',
           $5, NULL,
           jsonb_build_object(
               'redirect_count', (SELECT count(*) FROM inserted),
               'removed_count', (SELECT count(*) FROM removed)
           ),
           $3
    FROM actor
    RETURNING audit_id
)
SELECT inserted.redirect_path
FROM inserted
JOIN new_audit ON TRUE
ORDER BY inserted.redirect_path
