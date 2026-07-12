WITH actor AS (
    SELECT sessions.session_id, sessions.user_id, sessions.assurance,
           users.normalized_email
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $3::bigint
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
),
locked_invitation AS (
    SELECT invitations.*
    FROM auth_invitations AS invitations
    JOIN actor ON actor.normalized_email = invitations.normalized_email
    WHERE invitations.token_hash = $2
    FOR UPDATE OF invitations
),
locked_organization AS (
    SELECT organizations.organization_id
    FROM auth_organizations AS organizations
    JOIN locked_invitation
      ON locked_invitation.organization_id = organizations.organization_id
    WHERE organizations.status = 'active'
    FOR UPDATE OF organizations
),
eligible AS (
    SELECT locked_invitation.*, actor.user_id, actor.session_id
    FROM locked_invitation
    JOIN locked_organization ON TRUE
    JOIN actor ON TRUE
    WHERE locked_invitation.status = 'pending'
      AND locked_invitation.expires_at_ms > $3::bigint
      AND (
            locked_invitation.role_id NOT IN ('owner', 'admin')
            OR actor.assurance IN ('aal2', 'aal3')
          )
),
accepted_invitation AS (
    UPDATE auth_invitations AS invitations
    SET status = 'accepted', accepted_at_ms = $3,
        accepted_by = eligible.user_id, updated_at_ms = $3
    FROM eligible
    WHERE invitations.invitation_id = eligible.invitation_id
    RETURNING invitations.invitation_id, invitations.organization_id,
              invitations.role_id, eligible.user_id, eligible.session_id
),
consumed_token AS (
    UPDATE auth_one_time_tokens AS tokens
    SET consumed_at_ms = $3
    FROM accepted_invitation
    WHERE tokens.token_hash = $2
      AND tokens.purpose = 'invitation'
      AND tokens.consumed_at_ms IS NULL
    RETURNING tokens.token_hash
),
accepted_membership AS (
    INSERT INTO auth_memberships (
        organization_id, user_id, role_id, status, joined_at_ms, updated_at_ms
    )
    SELECT accepted_invitation.organization_id, accepted_invitation.user_id,
           accepted_invitation.role_id, 'active', $3, $3
    FROM accepted_invitation JOIN consumed_token ON TRUE
    ON CONFLICT (organization_id, user_id) DO UPDATE
    SET role_id = EXCLUDED.role_id, status = 'active', updated_at_ms = EXCLUDED.updated_at_ms
    RETURNING organization_id, user_id, role_id
),
revised AS (
    UPDATE auth_organizations AS organizations
    SET authorization_revision = organizations.authorization_revision + 1,
        updated_at_ms = $3
    FROM accepted_membership
    WHERE organizations.organization_id = accepted_membership.organization_id
      AND accepted_membership.role_id <> 'owner'
    RETURNING organizations.organization_id, organizations.name,
              organizations.status, organizations.created_at_ms
),
revision_result AS (
    SELECT organizations.organization_id, organizations.name,
           organizations.status, organizations.created_at_ms
    FROM accepted_membership
    JOIN auth_organizations AS organizations
      ON organizations.organization_id = accepted_membership.organization_id
    WHERE accepted_membership.role_id = 'owner'
    UNION ALL
    SELECT * FROM revised
),
selected_session AS (
    UPDATE auth_sessions AS sessions
    SET selected_organization_id = accepted_membership.organization_id,
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $3
    FROM accepted_membership
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.user_id = accepted_membership.user_id
    RETURNING sessions.session_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $4::text::uuid, accepted_membership.organization_id,
           accepted_membership.user_id, selected_session.session_id,
           'invitation.accept', 'invitation', accepted_invitation.invitation_id::text,
           'succeeded', $5,
           jsonb_build_object('role_id', accepted_membership.role_id), $3
    FROM accepted_membership
    JOIN accepted_invitation ON TRUE
    JOIN selected_session ON TRUE
    RETURNING audit_id
),
result AS (
    SELECT revision_result.organization_id, revision_result.name, revision_result.status,
           revision_result.created_at_ms, accepted_membership.role_id
    FROM revision_result
    JOIN accepted_membership ON TRUE
    JOIN new_audit ON TRUE
)
SELECT result.organization_id::text AS organization_id,
       result.name, result.status, result.created_at_ms,
       result.role_id,
       COALESCE(
           jsonb_agg(role_permissions.permission ORDER BY role_permissions.permission)
               FILTER (WHERE role_permissions.permission IS NOT NULL),
           '[]'::jsonb
       ) AS permissions
FROM result
LEFT JOIN auth_role_permissions AS role_permissions
  ON role_permissions.organization_id = result.organization_id
 AND role_permissions.role_id = result.role_id
GROUP BY result.organization_id, result.name, result.status,
         result.created_at_ms, result.role_id
