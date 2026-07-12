SELECT
    u.user_id::text AS user_id,
    u.primary_email,
    s.session_id::text AS session_id,
    s.selected_organization_id::text AS organization_id,
    s.assurance,
    s.created_at_ms,
    s.expires_at_ms,
    m.role_id,
    COALESCE(
        jsonb_agg(rp.permission ORDER BY rp.permission)
            FILTER (WHERE rp.permission IS NOT NULL),
        '[]'::jsonb
    ) AS permissions,
    active_policy.policy_revision,
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
LEFT JOIN auth_role_permissions rp
    ON rp.organization_id = m.organization_id
   AND rp.role_id = m.role_id
LEFT JOIN LATERAL (
    SELECT policy_revision
    FROM auth_policy_bundles
    WHERE status = 'active'
    LIMIT 1
) active_policy ON TRUE
WHERE s.session_id = $1::text::uuid
  AND s.revoked_at_ms IS NULL
  AND s.expires_at_ms > $2
  AND u.status = 'active'
  AND u.security_revision = s.user_security_revision
  AND (
      s.selected_organization_id IS NULL
      OR (
          organization.status = 'active'
          AND m.user_id IS NOT NULL
      )
  )
GROUP BY
    u.user_id,
    u.primary_email,
    s.session_id,
    s.selected_organization_id,
    s.assurance,
    s.created_at_ms,
    s.expires_at_ms,
    m.role_id,
    active_policy.policy_revision;
