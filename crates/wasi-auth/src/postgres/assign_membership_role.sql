WITH actor AS (
    SELECT sessions.session_id, sessions.user_id,
           EXISTS (
               SELECT 1
               FROM auth_role_permissions AS owner_permission
               WHERE owner_permission.organization_id = memberships.organization_id
                 AND owner_permission.role_id = memberships.role_id
                 AND owner_permission.permission = 'ownership.transfer'
           ) AS can_transfer_ownership
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    JOIN auth_memberships AS memberships
      ON memberships.user_id = sessions.user_id
     AND memberships.organization_id = $2::text::uuid
     AND memberships.status = 'active'
    JOIN auth_role_permissions AS permission
      ON permission.organization_id = memberships.organization_id
     AND permission.role_id = memberships.role_id
     AND permission.permission = 'member.manage'
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $5::bigint
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
target_membership AS (
    SELECT memberships.organization_id, memberships.user_id,
           memberships.role_id, memberships.joined_at_ms
    FROM auth_memberships AS memberships
    JOIN locked_organization
      ON locked_organization.organization_id = memberships.organization_id
    WHERE memberships.user_id = $3::text::uuid
      AND memberships.status = 'active'
    FOR UPDATE OF memberships
),
assignable_role AS (
    SELECT roles.organization_id, roles.role_id
    FROM auth_roles AS roles
    JOIN locked_organization
      ON locked_organization.organization_id = roles.organization_id
    WHERE roles.role_id = $4
),
eligible AS (
    SELECT target_membership.*, assignable_role.role_id AS next_role_id
    FROM target_membership
    JOIN assignable_role ON TRUE
    JOIN actor ON TRUE
    WHERE (
            target_membership.role_id NOT IN ('owner')
            AND assignable_role.role_id NOT IN ('owner')
          )
       OR actor.can_transfer_ownership
      AND (
            assignable_role.role_id = 'owner'
            OR target_membership.role_id <> 'owner'
            OR (SELECT count(*) FROM auth_memberships AS owners
                WHERE owners.organization_id = target_membership.organization_id
                  AND owners.role_id = 'owner'
                  AND owners.status = 'active') > 1
          )
),
updated AS (
    UPDATE auth_memberships AS memberships
    SET role_id = eligible.next_role_id, updated_at_ms = $5
    FROM eligible
    WHERE memberships.organization_id = eligible.organization_id
      AND memberships.user_id = eligible.user_id
    RETURNING memberships.organization_id, memberships.user_id,
              memberships.role_id, memberships.status, memberships.joined_at_ms,
              eligible.role_id AS previous_role_id
),
revised AS (
    UPDATE auth_organizations AS organizations
    SET authorization_revision = organizations.authorization_revision + 1,
        updated_at_ms = $5
    FROM updated
    WHERE organizations.organization_id = updated.organization_id
      AND ((updated.previous_role_id = 'owner') = (updated.role_id = 'owner'))
    RETURNING organizations.organization_id
),
revision_result AS (
    SELECT updated.organization_id
    FROM updated
    WHERE (updated.previous_role_id = 'owner') <> (updated.role_id = 'owner')
    UNION ALL
    SELECT revised.organization_id FROM revised
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $6::text::uuid, updated.organization_id, actor.user_id, actor.session_id,
           'member.role.assign', 'membership', updated.user_id::text, 'succeeded',
           $7, jsonb_build_object('role_id', updated.role_id), $5
    FROM updated
    JOIN revision_result ON revision_result.organization_id = updated.organization_id
    JOIN actor ON TRUE
    RETURNING audit_id
)
SELECT updated.organization_id::text AS organization_id,
       updated.user_id::text AS user_id,
       users.primary_email,
       updated.role_id,
       updated.status,
       updated.joined_at_ms
FROM updated
JOIN auth_users AS users ON users.user_id = updated.user_id
JOIN new_audit ON TRUE
