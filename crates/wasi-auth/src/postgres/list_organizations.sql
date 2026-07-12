SELECT
    organizations.organization_id::text AS organization_id,
    organizations.name,
    organizations.status,
    organizations.created_at_ms,
    memberships.role_id,
    COALESCE(
        jsonb_agg(role_permissions.permission ORDER BY role_permissions.permission)
            FILTER (WHERE role_permissions.permission IS NOT NULL),
        '[]'::jsonb
    ) AS permissions
FROM auth_memberships AS memberships
JOIN auth_organizations AS organizations
  ON organizations.organization_id = memberships.organization_id
LEFT JOIN auth_role_permissions AS role_permissions
  ON role_permissions.organization_id = memberships.organization_id
 AND role_permissions.role_id = memberships.role_id
WHERE memberships.user_id = $1::text::uuid
  AND memberships.status = 'active'
  AND organizations.status = 'active'
GROUP BY
    organizations.organization_id,
    organizations.name,
    organizations.status,
    organizations.created_at_ms,
    memberships.role_id
ORDER BY organizations.created_at_ms, organizations.organization_id
