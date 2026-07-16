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
     AND permission.permission = 'member.invite'
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $4::bigint
      AND sessions.user_security_revision = users.security_revision
      AND sessions.assurance IN ('aal2', 'aal3')
      AND users.status = 'active'
),
locked_invitation AS (
    SELECT invitations.invitation_id, invitations.organization_id,
           invitations.normalized_email, invitations.role_id,
           invitations.token_hash, invitations.status, invitations.expires_at_ms
    FROM auth_invitations AS invitations
    JOIN actor ON TRUE
    WHERE invitations.invitation_id = $3::text::uuid
      AND invitations.organization_id = $2::text::uuid
      AND invitations.status = 'pending'
    FOR UPDATE OF invitations
),
revoked_invitation AS (
    UPDATE auth_invitations AS invitations
    SET status = 'revoked', updated_at_ms = $4
    FROM locked_invitation
    WHERE invitations.invitation_id = locked_invitation.invitation_id
    RETURNING invitations.invitation_id, invitations.organization_id,
              invitations.normalized_email, invitations.role_id,
              invitations.status, invitations.expires_at_ms,
              locked_invitation.token_hash AS prior_token_hash
),
consumed_token AS (
    UPDATE auth_one_time_tokens AS tokens
    SET consumed_at_ms = $4
    FROM revoked_invitation
    WHERE tokens.token_hash = revoked_invitation.prior_token_hash
      AND tokens.purpose = 'invitation'
      AND tokens.consumed_at_ms IS NULL
    RETURNING tokens.token_hash
),
token_barrier AS (
    SELECT count(*) AS consumed FROM consumed_token
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $5::text::uuid, revoked_invitation.organization_id,
           actor.user_id, actor.session_id,
           'member.invite.revoke', 'invitation',
           revoked_invitation.invitation_id::text, 'succeeded',
           $6, jsonb_build_object('role_id', revoked_invitation.role_id), $4
    FROM revoked_invitation
    JOIN actor ON TRUE
    CROSS JOIN token_barrier
    RETURNING audit_id
)
SELECT revoked_invitation.invitation_id::text AS invitation_id,
       revoked_invitation.organization_id::text AS organization_id,
       revoked_invitation.normalized_email,
       revoked_invitation.role_id,
       revoked_invitation.status,
       revoked_invitation.expires_at_ms
FROM revoked_invitation
JOIN new_audit ON TRUE
