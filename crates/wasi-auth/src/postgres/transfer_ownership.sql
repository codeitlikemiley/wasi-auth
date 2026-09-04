-- Atomic ownership transfer under AAL2 + ownership.transfer.
-- Target becomes owner first (never zero owners), then actor is demoted to admin.
-- Parameters:
--   $1 session_id, $2 organization_id, $3 target_user_id,
--   $4 now_ms, $5 audit_id, $6 request_id
WITH actor AS (
    SELECT sessions.session_id, sessions.user_id, memberships.role_id AS actor_role_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    JOIN auth_memberships AS memberships
      ON memberships.user_id = sessions.user_id
     AND memberships.organization_id = $2::text::uuid
     AND memberships.status = 'active'
    JOIN auth_role_permissions AS permission
      ON permission.organization_id = memberships.organization_id
     AND permission.role_id = memberships.role_id
     AND permission.permission = 'ownership.transfer'
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $4::bigint
      AND sessions.user_security_revision = users.security_revision
      AND sessions.assurance IN ('aal2', 'aal3')
      AND users.status = 'active'
      AND sessions.user_id <> $3::text::uuid
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
           memberships.role_id, memberships.joined_at_ms, memberships.status
    FROM auth_memberships AS memberships
    JOIN locked_organization
      ON locked_organization.organization_id = memberships.organization_id
    WHERE memberships.user_id = $3::text::uuid
      AND memberships.status = 'active'
    FOR UPDATE OF memberships
),
actor_membership AS (
    SELECT memberships.organization_id, memberships.user_id,
           memberships.role_id, memberships.joined_at_ms, memberships.status
    FROM auth_memberships AS memberships
    JOIN locked_organization
      ON locked_organization.organization_id = memberships.organization_id
    JOIN actor ON actor.user_id = memberships.user_id
    WHERE memberships.status = 'active'
    FOR UPDATE OF memberships
),
-- Promote target to owner first so owner_count never hits zero.
promoted_target AS (
    UPDATE auth_memberships AS memberships
    SET role_id = 'owner', updated_at_ms = $4
    FROM target_membership, actor_membership
    WHERE memberships.organization_id = target_membership.organization_id
      AND memberships.user_id = target_membership.user_id
    RETURNING memberships.organization_id, memberships.user_id,
              memberships.role_id, memberships.status, memberships.joined_at_ms,
              target_membership.role_id AS previous_target_role_id
),
demoted_actor AS (
    UPDATE auth_memberships AS memberships
    SET role_id = 'admin', updated_at_ms = $4
    FROM actor_membership, promoted_target
    WHERE memberships.organization_id = actor_membership.organization_id
      AND memberships.user_id = actor_membership.user_id
      AND memberships.role_id = 'owner'
    RETURNING memberships.organization_id, memberships.user_id,
              memberships.role_id AS new_actor_role_id,
              actor_membership.role_id AS previous_owner_role_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $5::text::uuid, promoted_target.organization_id, actor.user_id, actor.session_id,
           'ownership.transfer', 'organization', promoted_target.organization_id::text, 'succeeded',
           $6,
           jsonb_build_object(
               'previous_owner_id', actor.user_id::text,
               'new_owner_id', promoted_target.user_id::text,
               'previous_target_role_id', promoted_target.previous_target_role_id,
               'actor_new_role_id', COALESCE(demoted_actor.new_actor_role_id, actor.actor_role_id)
           ),
           $4
    FROM promoted_target
    JOIN actor ON TRUE
    LEFT JOIN demoted_actor ON TRUE
    RETURNING audit_id
)
SELECT promoted_target.organization_id::text AS organization_id,
       promoted_target.user_id::text AS user_id,
       users.primary_email,
       promoted_target.role_id,
       promoted_target.status,
       promoted_target.joined_at_ms,
       actor.user_id::text AS previous_owner_id
FROM promoted_target
JOIN auth_users AS users ON users.user_id = promoted_target.user_id
JOIN actor ON TRUE
JOIN new_audit ON TRUE
