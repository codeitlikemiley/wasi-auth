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
target_membership AS (
    SELECT memberships.organization_id, memberships.user_id,
           memberships.role_id
    FROM auth_memberships AS memberships
    JOIN locked_organization
      ON locked_organization.organization_id = memberships.organization_id
    WHERE memberships.user_id = $3::text::uuid
      AND memberships.status = 'active'
    FOR UPDATE OF memberships
),
eligible AS (
    SELECT target_membership.*
    FROM target_membership
    JOIN actor ON TRUE
    WHERE target_membership.role_id <> 'owner'
       OR (
            actor.can_transfer_ownership
            AND (SELECT count(*) FROM auth_memberships AS owners
                 WHERE owners.organization_id = target_membership.organization_id
                   AND owners.role_id = 'owner'
                   AND owners.status = 'active') > 1
          )
),
removed AS (
    UPDATE auth_memberships AS memberships
    SET status = 'removed', updated_at_ms = $4
    FROM eligible
    WHERE memberships.organization_id = eligible.organization_id
      AND memberships.user_id = eligible.user_id
    RETURNING memberships.organization_id, memberships.user_id, eligible.role_id
),
cleared_sessions AS (
    UPDATE auth_sessions AS sessions
    SET selected_organization_id = NULL,
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $4
    FROM removed
    WHERE sessions.user_id = removed.user_id
      AND sessions.selected_organization_id = removed.organization_id
    RETURNING sessions.session_id
),
session_barrier AS (
    SELECT count(*) AS cleared FROM cleared_sessions
),
revised AS (
    UPDATE auth_organizations AS organizations
    SET authorization_revision = organizations.authorization_revision + 1,
        updated_at_ms = $4
    FROM removed CROSS JOIN session_barrier
    WHERE organizations.organization_id = removed.organization_id
      AND removed.role_id <> 'owner'
    RETURNING organizations.organization_id
),
revision_result AS (
    SELECT removed.organization_id
    FROM removed
    WHERE removed.role_id = 'owner'
    UNION ALL
    SELECT revised.organization_id FROM revised
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $5::text::uuid, removed.organization_id, actor.user_id, actor.session_id,
           'member.remove', 'membership', removed.user_id::text, 'succeeded',
           $6, '{}', $4
    FROM removed
    JOIN revision_result ON revision_result.organization_id = removed.organization_id
    JOIN actor ON TRUE
    RETURNING audit_id
)
SELECT 'removed'::text AS outcome
FROM new_audit
