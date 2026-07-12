WITH actor AS (
    SELECT sessions.user_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $3::bigint
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
),
membership AS (
    SELECT memberships.user_id, memberships.role_id
    FROM actor
    JOIN auth_memberships AS memberships ON memberships.user_id = actor.user_id
    WHERE memberships.organization_id = $2::text::uuid
      AND memberships.status = 'active'
)
SELECT organizations.organization_id::text AS organization_id,
       organizations.name,
       organizations.status,
       organizations.created_at_ms,
       membership.role_id,
       COALESCE(
           jsonb_agg(role_permissions.permission ORDER BY role_permissions.permission)
               FILTER (WHERE role_permissions.permission IS NOT NULL),
           '[]'::jsonb
       ) AS permissions
FROM membership
JOIN auth_organizations AS organizations
  ON organizations.organization_id = $2::text::uuid
 AND organizations.status = 'active'
LEFT JOIN auth_role_permissions AS role_permissions
  ON role_permissions.organization_id = organizations.organization_id
 AND role_permissions.role_id = membership.role_id
GROUP BY organizations.organization_id, organizations.name, organizations.status,
         organizations.created_at_ms, membership.role_id
