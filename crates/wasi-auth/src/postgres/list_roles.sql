WITH actor AS (
    SELECT sessions.user_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    JOIN auth_memberships AS memberships
      ON memberships.user_id = sessions.user_id
     AND memberships.organization_id = $2::text::uuid
     AND memberships.status = 'active'
    JOIN auth_role_permissions AS permission
      ON permission.organization_id = memberships.organization_id
     AND permission.role_id = memberships.role_id
     AND permission.permission = 'role.view'
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $3::bigint
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
)
SELECT roles.organization_id::text AS organization_id,
       roles.role_id,
       roles.name,
       roles.built_in,
       COALESCE(
           jsonb_agg(role_permissions.permission ORDER BY role_permissions.permission)
               FILTER (WHERE role_permissions.permission IS NOT NULL),
           '[]'::jsonb
       ) AS permissions
FROM actor
JOIN auth_roles AS roles ON roles.organization_id = $2::text::uuid
LEFT JOIN auth_role_permissions AS role_permissions
  ON role_permissions.organization_id = roles.organization_id
 AND role_permissions.role_id = roles.role_id
GROUP BY roles.organization_id, roles.role_id, roles.name, roles.built_in
ORDER BY roles.built_in DESC, roles.name, roles.role_id
