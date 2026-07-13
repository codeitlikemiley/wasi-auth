WITH actor AS (
    SELECT sessions.session_id, sessions.user_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    JOIN auth_memberships AS memberships
      ON memberships.user_id = sessions.user_id
     AND memberships.organization_id = $2::text::uuid
     AND memberships.status = 'active'
    JOIN auth_role_permissions AS permission
      ON permission.organization_id = memberships.organization_id
     AND permission.role_id = memberships.role_id
     AND permission.permission = 'role.manage'
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $6::bigint
      AND sessions.user_security_revision = users.security_revision
      AND sessions.assurance IN ('aal2', 'aal3')
      AND users.status = 'active'
),
locked_organization AS (
    SELECT organizations.organization_id
    FROM auth_organizations AS organizations
    JOIN actor ON TRUE
    WHERE organizations.organization_id = $2::text::uuid
      AND organizations.status = 'active'
    FOR UPDATE OF organizations
),
saved_role AS (
    INSERT INTO auth_roles (
        organization_id, role_id, name, built_in, created_at_ms, updated_at_ms
    )
    SELECT locked_organization.organization_id, $3, $4, FALSE, $6, $6
    FROM locked_organization
    ON CONFLICT (organization_id, role_id) DO UPDATE
    SET name = EXCLUDED.name, updated_at_ms = EXCLUDED.updated_at_ms
    WHERE auth_roles.built_in = FALSE
    RETURNING organization_id, role_id, name, built_in
),
deleted_permissions AS (
    DELETE FROM auth_role_permissions AS permissions
    USING saved_role
    WHERE permissions.organization_id = saved_role.organization_id
      AND permissions.role_id = saved_role.role_id
    RETURNING permissions.permission
),
delete_barrier AS (
    SELECT count(*) AS deleted FROM deleted_permissions
),
inserted_permissions AS (
    INSERT INTO auth_role_permissions (organization_id, role_id, permission)
    SELECT saved_role.organization_id, saved_role.role_id, input.permission
    FROM saved_role
    CROSS JOIN delete_barrier
    CROSS JOIN LATERAL jsonb_array_elements_text($5::jsonb) AS input(permission)
    RETURNING permission
),
permission_barrier AS (
    SELECT count(*) AS inserted FROM inserted_permissions
),
revised AS (
    UPDATE auth_organizations AS organizations
    SET authorization_revision = organizations.authorization_revision + 1,
        updated_at_ms = $6
    FROM saved_role CROSS JOIN permission_barrier
    WHERE organizations.organization_id = saved_role.organization_id
    RETURNING organizations.organization_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $7::text::uuid, revised.organization_id, actor.user_id, actor.session_id,
           'role.manage', 'role', saved_role.role_id, 'succeeded',
           $8, jsonb_build_object('permissions', $5::jsonb), $6
    FROM revised JOIN saved_role ON TRUE JOIN actor ON TRUE
    RETURNING audit_id
)
SELECT saved_role.organization_id::text AS organization_id,
       saved_role.role_id, saved_role.name, saved_role.built_in,
       $5::jsonb AS permissions
FROM saved_role JOIN new_audit ON TRUE
