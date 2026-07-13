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
SELECT TRUE AS authorized,
       invitations.invitation_id::text AS invitation_id,
       invitations.organization_id::text AS organization_id,
       invitations.normalized_email,
       invitations.role_id,
       invitations.status,
       invitations.expires_at_ms
FROM actor
LEFT JOIN auth_invitations AS invitations
  ON invitations.organization_id = $2::text::uuid
ORDER BY invitations.created_at_ms DESC NULLS LAST
