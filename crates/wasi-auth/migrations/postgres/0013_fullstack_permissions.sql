-- Canonical fullstack application permissions for existing built-in roles.

DELETE FROM auth_role_permissions
WHERE role_id IN ('owner', 'admin', 'member', 'viewer')
  AND split_part(permission, '.', 1) IN ('dashboard', 'resource', 'query', 'vault');

INSERT INTO auth_role_permissions (organization_id, role_id, permission)
SELECT roles.organization_id, grants.role_id, grants.permission
FROM auth_roles AS roles
JOIN (
    VALUES
        ('owner', 'dashboard.view'),
        ('owner', 'dashboard.manage'),
        ('owner', 'resource.view'),
        ('owner', 'resource.manage'),
        ('owner', 'query.view'),
        ('owner', 'query.manage'),
        ('owner', 'query.execute'),
        ('owner', 'query.execute_mutation'),
        ('owner', 'vault.view'),
        ('owner', 'vault.manage'),
        ('owner', 'vault.reveal'),
        ('admin', 'dashboard.view'),
        ('admin', 'dashboard.manage'),
        ('admin', 'resource.view'),
        ('admin', 'resource.manage'),
        ('admin', 'query.view'),
        ('admin', 'query.manage'),
        ('admin', 'query.execute'),
        ('admin', 'query.execute_mutation'),
        ('admin', 'vault.view'),
        ('admin', 'vault.manage'),
        ('admin', 'vault.reveal'),
        ('member', 'dashboard.view'),
        ('member', 'query.view'),
        ('member', 'query.execute'),
        ('viewer', 'dashboard.view')
) AS grants(role_id, permission)
  ON grants.role_id = roles.role_id
WHERE roles.built_in = TRUE
ON CONFLICT DO NOTHING;
