WITH actor AS (
    SELECT sessions.session_id, sessions.user_id, memberships.role_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    JOIN auth_memberships AS memberships
      ON memberships.user_id = sessions.user_id
     AND memberships.organization_id = $2::text::uuid
     AND memberships.status = 'active'
    JOIN auth_role_permissions AS permission
      ON permission.organization_id = memberships.organization_id
     AND permission.role_id = memberships.role_id
     AND permission.permission = 'organization.update'
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $4::bigint
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
updated AS (
    UPDATE auth_organizations AS organizations
    SET name = $3, updated_at_ms = $4
    FROM locked_organization
    WHERE organizations.organization_id = locked_organization.organization_id
    RETURNING organizations.organization_id, organizations.name, organizations.slug,
              organizations.status, organizations.created_at_ms
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $5::text::uuid, updated.organization_id, actor.user_id, actor.session_id,
           'organization.update', 'organization', updated.organization_id::text,
           'succeeded', $6, '{}', $4
    FROM updated JOIN actor ON TRUE
    RETURNING audit_id
)
SELECT updated.organization_id::text AS organization_id,
       updated.name, updated.slug, updated.status, updated.created_at_ms,
       actor.role_id,
       COALESCE(
           jsonb_agg(role_permissions.permission ORDER BY role_permissions.permission)
               FILTER (WHERE role_permissions.permission IS NOT NULL),
           '[]'::jsonb
       ) AS permissions
FROM updated
JOIN actor ON TRUE
JOIN new_audit ON TRUE
LEFT JOIN auth_role_permissions AS role_permissions
  ON role_permissions.organization_id = updated.organization_id
 AND role_permissions.role_id = actor.role_id
GROUP BY updated.organization_id, updated.name, updated.slug, updated.status,
         updated.created_at_ms, actor.role_id
