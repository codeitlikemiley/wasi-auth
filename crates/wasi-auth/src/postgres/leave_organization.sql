-- Self-remove membership without member.manage.
-- Fails closed when the actor is the last active owner (owner invariant).
-- Parameters:
--   $1 session_id, $2 organization_id,
--   $3 now_ms, $4 audit_id, $5 request_id
WITH actor AS (
    SELECT sessions.session_id, sessions.user_id, memberships.role_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    JOIN auth_memberships AS memberships
      ON memberships.user_id = sessions.user_id
     AND memberships.organization_id = $2::text::uuid
     AND memberships.status = 'active'
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $3::bigint
      AND sessions.user_security_revision = users.security_revision
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
    SELECT memberships.organization_id, memberships.user_id, memberships.role_id
    FROM auth_memberships AS memberships
    JOIN locked_organization
      ON locked_organization.organization_id = memberships.organization_id
    JOIN actor ON actor.user_id = memberships.user_id
    WHERE memberships.status = 'active'
    FOR UPDATE OF memberships
),
-- Last active owner cannot leave (preserve auth_organization_requires_owner).
eligible AS (
    SELECT target_membership.*
    FROM target_membership
    WHERE target_membership.role_id <> 'owner'
       OR (SELECT count(*) FROM auth_memberships AS owners
           WHERE owners.organization_id = target_membership.organization_id
             AND owners.role_id = 'owner'
             AND owners.status = 'active') > 1
),
removed AS (
    UPDATE auth_memberships AS memberships
    SET status = 'removed', updated_at_ms = $3
    FROM eligible
    WHERE memberships.organization_id = eligible.organization_id
      AND memberships.user_id = eligible.user_id
    RETURNING memberships.organization_id, memberships.user_id, eligible.role_id
),
cleared_sessions AS (
    UPDATE auth_sessions AS sessions
    SET selected_organization_id = NULL,
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $3
    FROM removed
    WHERE sessions.user_id = removed.user_id
      AND sessions.selected_organization_id = removed.organization_id
    RETURNING sessions.session_id
),
session_barrier AS (
    SELECT count(*) AS cleared FROM cleared_sessions
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $4::text::uuid, removed.organization_id, actor.user_id, actor.session_id,
           'member.leave', 'membership', removed.user_id::text, 'succeeded',
           $5, jsonb_build_object('previous_role_id', removed.role_id), $3
    FROM removed
    CROSS JOIN session_barrier
    JOIN actor ON TRUE
    RETURNING audit_id
)
SELECT 'left'::text AS outcome
FROM new_audit
