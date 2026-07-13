WITH actor AS (
    SELECT sessions.user_id,
           EXISTS (
               SELECT 1 FROM auth_system_administrators AS administrators
               WHERE administrators.user_id = sessions.user_id
                 AND administrators.revoked_at_ms IS NULL
                 AND sessions.assurance IN ('aal2', 'aal3')
           ) AS system_administrator
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $5::bigint
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
),
authorized AS (
    SELECT actor.user_id
    FROM actor
    WHERE actor.system_administrator
       OR (
            $2::text IS NOT NULL
            AND EXISTS (
                SELECT 1
                FROM auth_memberships AS memberships
                JOIN auth_role_permissions AS permission
                  ON permission.organization_id = memberships.organization_id
                 AND permission.role_id = memberships.role_id
                 AND permission.permission = 'audit.view'
                WHERE memberships.organization_id = $2::text::uuid
                  AND memberships.user_id = actor.user_id
                  AND memberships.status = 'active'
            )
          )
),
events AS (
    SELECT audit.sequence,
           audit.organization_id::text AS organization_id,
           COALESCE(audit.actor_user_id::text, 'system') AS actor_user_id,
           audit.action,
           audit.resource_type,
           audit.resource_id,
           audit.outcome,
           audit.occurred_at_ms
    FROM auth_audit_log AS audit
    JOIN authorized ON TRUE
    WHERE audit.sequence > $3::bigint
      AND ($2::text IS NULL OR audit.organization_id = $2::text::uuid)
    ORDER BY audit.sequence
    LIMIT $4::bigint
)
SELECT TRUE AS authorized,
       events.sequence,
       events.organization_id,
       events.actor_user_id,
       events.action,
       events.resource_type,
       events.resource_id,
       events.outcome,
       events.occurred_at_ms
FROM authorized
LEFT JOIN events ON TRUE
ORDER BY events.sequence NULLS LAST
