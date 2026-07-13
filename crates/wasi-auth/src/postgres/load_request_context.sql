SELECT
    u.user_id::text AS user_id,
    u.primary_email,
    s.session_id::text AS session_id,
    s.selected_organization_id::text AS organization_id,
    s.assurance,
    s.created_at_ms,
    s.expires_at_ms,
    s.session_revision,
    s.user_security_revision,
    organization.authorization_revision AS organization_authorization_revision,
    m.role_id,
    COALESCE(
        (
            SELECT jsonb_agg(role_permission.permission ORDER BY role_permission.permission)
            FROM auth_role_permissions role_permission
            WHERE role_permission.organization_id = m.organization_id
              AND role_permission.role_id = m.role_id
        ),
        '[]'::jsonb
    ) AS permissions,
    (
        SELECT policy_bundle.policy_revision
        FROM auth_policy_bundles policy_bundle
        WHERE policy_bundle.status = 'active'
        LIMIT 1
    ) AS policy_revision,
    EXISTS (
        SELECT 1 FROM auth_system_administrators administrator
        WHERE administrator.user_id = u.user_id
          AND administrator.revoked_at_ms IS NULL
    ) AS system_administrator
FROM auth_sessions s
JOIN auth_users u ON u.user_id = s.user_id
LEFT JOIN auth_organizations organization
    ON organization.organization_id = s.selected_organization_id
LEFT JOIN auth_memberships m
    ON m.organization_id = s.selected_organization_id
   AND m.user_id = s.user_id
   AND m.status = 'active'
WHERE s.session_id = $1::text::uuid
  AND s.revoked_at_ms IS NULL
  AND s.expires_at_ms > $2
  AND u.status = 'active'
  AND u.security_revision = s.user_security_revision
  AND (
      $3::text = ''
      OR EXISTS (
          SELECT 1
          FROM auth_signing_keys signing_key
          WHERE signing_key.key_id = $3
            AND signing_key.status IN ('active', 'retired')
      )
  )
  AND (
      s.selected_organization_id IS NULL
      OR (
          organization.status = 'active'
          AND m.user_id IS NOT NULL
      )
  );
