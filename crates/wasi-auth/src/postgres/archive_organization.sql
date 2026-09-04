-- Soft-deactivate (archive) an organization under AAL2 + ownership.transfer.
-- Revokes pending invitations, clears selected_organization for sessions on this
-- org, bumps authorization_revision. Does not freeze memberships or emit bulk
-- relationship revokes — product surfaces gate on status = 'active'.
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
    JOIN auth_role_permissions AS permission
      ON permission.organization_id = memberships.organization_id
     AND permission.role_id = memberships.role_id
     AND permission.permission = 'ownership.transfer'
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $3::bigint
      AND sessions.user_security_revision = users.security_revision
      AND sessions.assurance IN ('aal2', 'aal3')
      AND users.status = 'active'
),
locked_organization AS (
    SELECT organizations.organization_id, organizations.name, organizations.slug,
           organizations.status, organizations.created_at_ms
    FROM auth_organizations AS organizations
    JOIN actor ON TRUE
    WHERE organizations.organization_id = $2::text::uuid
      AND organizations.status = 'active'
    FOR UPDATE OF organizations
),
archived AS (
    UPDATE auth_organizations AS organizations
    SET status = 'archived',
        authorization_revision = organizations.authorization_revision + 1,
        updated_at_ms = $3
    FROM locked_organization
    WHERE organizations.organization_id = locked_organization.organization_id
    RETURNING organizations.organization_id, organizations.name, organizations.slug,
              organizations.status, organizations.created_at_ms
),
revoked_invitations AS (
    UPDATE auth_invitations AS invitations
    SET status = 'revoked', updated_at_ms = $3
    FROM archived
    WHERE invitations.organization_id = archived.organization_id
      AND invitations.status = 'pending'
    RETURNING invitations.invitation_id, invitations.token_hash
),
consumed_tokens AS (
    UPDATE auth_one_time_tokens AS tokens
    SET consumed_at_ms = $3
    FROM revoked_invitations
    WHERE tokens.token_hash = revoked_invitations.token_hash
      AND tokens.purpose = 'invitation'
      AND tokens.consumed_at_ms IS NULL
    RETURNING tokens.token_hash
),
token_barrier AS (
    SELECT count(*) AS consumed FROM consumed_tokens
),
cleared_sessions AS (
    UPDATE auth_sessions AS sessions
    SET selected_organization_id = NULL,
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $3
    FROM archived, token_barrier
    WHERE sessions.selected_organization_id = archived.organization_id
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
    SELECT $4::text::uuid, archived.organization_id, actor.user_id, actor.session_id,
           'organization.archive', 'organization', archived.organization_id::text, 'succeeded',
           $5,
           jsonb_build_object(
               'previous_status', 'active',
               'status', 'archived',
               'revoked_invitations', (SELECT count(*) FROM revoked_invitations),
               'cleared_sessions', session_barrier.cleared
           ),
           $3
    FROM archived
    JOIN actor ON TRUE
    CROSS JOIN session_barrier
    RETURNING audit_id
)
SELECT archived.organization_id::text AS organization_id,
       archived.name,
       archived.slug,
       archived.status,
       archived.created_at_ms,
       actor.role_id,
       COALESCE(
           jsonb_agg(role_permissions.permission ORDER BY role_permissions.permission)
               FILTER (WHERE role_permissions.permission IS NOT NULL),
           '[]'::jsonb
       ) AS permissions
FROM archived
JOIN actor ON TRUE
JOIN new_audit ON TRUE
LEFT JOIN auth_role_permissions AS role_permissions
  ON role_permissions.organization_id = archived.organization_id
 AND role_permissions.role_id = actor.role_id
GROUP BY archived.organization_id, archived.name, archived.slug, archived.status,
         archived.created_at_ms, actor.role_id
