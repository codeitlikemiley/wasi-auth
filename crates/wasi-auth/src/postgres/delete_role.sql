-- Delete a custom (non-built-in) role under AAL2 + role.manage.
-- Fails closed when any active membership or pending invitation still uses the role.
-- Residual non-active memberships / non-pending invitations are re-pointed to
-- built-in `member` so the role row can be removed under FK constraints.
-- Parameters:
--   $1 session_id, $2 organization_id, $3 role_id,
--   $4 now_ms, $5 audit_id, $6 request_id
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
target_role AS (
    SELECT roles.organization_id, roles.role_id, roles.name, roles.built_in
    FROM auth_roles AS roles
    JOIN locked_organization
      ON locked_organization.organization_id = roles.organization_id
    WHERE roles.role_id = $3
      AND roles.built_in = FALSE
    FOR UPDATE OF roles
),
usage AS (
    SELECT
        COALESCE((
            SELECT count(*)::bigint
            FROM auth_memberships AS memberships
            JOIN target_role
              ON memberships.organization_id = target_role.organization_id
             AND memberships.role_id = target_role.role_id
            WHERE memberships.status = 'active'
        ), 0) AS member_count,
        COALESCE((
            SELECT count(*)::bigint
            FROM auth_invitations AS invitations
            JOIN target_role
              ON invitations.organization_id = target_role.organization_id
             AND invitations.role_id = target_role.role_id
            WHERE invitations.status = 'pending'
        ), 0) AS invitation_count
),
blocked AS (
    SELECT target_role.organization_id,
           target_role.role_id,
           target_role.name,
           usage.member_count,
           usage.invitation_count
    FROM target_role
    CROSS JOIN usage
    WHERE usage.member_count > 0
       OR usage.invitation_count > 0
),
eligible AS (
    SELECT target_role.organization_id, target_role.role_id, target_role.name
    FROM target_role
    CROSS JOIN usage
    WHERE usage.member_count = 0
      AND usage.invitation_count = 0
),
retargeted_memberships AS (
    UPDATE auth_memberships AS memberships
    SET role_id = 'member',
        updated_at_ms = $4
    FROM eligible
    WHERE memberships.organization_id = eligible.organization_id
      AND memberships.role_id = eligible.role_id
      AND memberships.status <> 'active'
    RETURNING memberships.user_id
),
membership_barrier AS (
    SELECT count(*) AS retargeted FROM retargeted_memberships
),
retargeted_invitations AS (
    UPDATE auth_invitations AS invitations
    SET role_id = 'member',
        updated_at_ms = $4
    FROM eligible, membership_barrier
    WHERE invitations.organization_id = eligible.organization_id
      AND invitations.role_id = eligible.role_id
      AND invitations.status <> 'pending'
    RETURNING invitations.invitation_id
),
invitation_barrier AS (
    SELECT count(*) AS retargeted FROM retargeted_invitations
),
deleted_role AS (
    DELETE FROM auth_roles AS roles
    USING eligible, invitation_barrier
    WHERE roles.organization_id = eligible.organization_id
      AND roles.role_id = eligible.role_id
    RETURNING roles.organization_id, roles.role_id, roles.name
),
revised AS (
    UPDATE auth_organizations AS organizations
    SET authorization_revision = organizations.authorization_revision + 1,
        updated_at_ms = $4
    FROM deleted_role
    WHERE organizations.organization_id = deleted_role.organization_id
    RETURNING organizations.organization_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $5::text::uuid, revised.organization_id, actor.user_id, actor.session_id,
           'role.manage', 'role', deleted_role.role_id, 'succeeded',
           $6, jsonb_build_object('operation', 'delete', 'name', deleted_role.name), $4
    FROM revised
    JOIN deleted_role ON TRUE
    JOIN actor ON TRUE
    RETURNING audit_id
)
SELECT 'deleted'::text AS outcome,
       deleted_role.role_id,
       deleted_role.name,
       0::bigint AS member_count,
       0::bigint AS invitation_count
FROM deleted_role
JOIN new_audit ON TRUE
UNION ALL
SELECT 'in_use'::text AS outcome,
       blocked.role_id,
       blocked.name,
       blocked.member_count,
       blocked.invitation_count
FROM blocked
