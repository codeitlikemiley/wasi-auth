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
     AND permission.permission = 'member.view'
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $3::bigint
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
)
SELECT memberships.organization_id::text AS organization_id,
       memberships.user_id::text AS user_id,
       users.primary_email,
       memberships.role_id,
       memberships.status,
       memberships.joined_at_ms
FROM actor
JOIN auth_memberships AS memberships
  ON memberships.organization_id = $2::text::uuid
JOIN auth_users AS users ON users.user_id = memberships.user_id
ORDER BY users.primary_email, memberships.user_id
