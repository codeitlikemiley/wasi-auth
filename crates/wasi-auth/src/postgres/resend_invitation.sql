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
      AND sessions.expires_at_ms > $12::bigint
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
consumed_token AS (
    UPDATE auth_one_time_tokens AS tokens
    SET consumed_at_ms = $12
    FROM locked_invitation
    WHERE tokens.token_hash = locked_invitation.token_hash
      AND tokens.purpose = 'invitation'
      AND tokens.consumed_at_ms IS NULL
    RETURNING tokens.token_hash
),
token_barrier AS (
    SELECT count(*) AS consumed FROM consumed_token
),
rotated_invitation AS (
    UPDATE auth_invitations AS invitations
    SET token_hash = $4,
        expires_at_ms = $5,
        updated_at_ms = $12
    FROM locked_invitation
    CROSS JOIN token_barrier
    WHERE invitations.invitation_id = locked_invitation.invitation_id
    RETURNING invitations.invitation_id, invitations.organization_id,
              invitations.normalized_email, invitations.role_id,
              invitations.status, invitations.expires_at_ms, invitations.token_hash
),
new_token AS (
    INSERT INTO auth_one_time_tokens (
        token_hash, purpose, subject_hint, redirect_uri, payload,
        expires_at_ms, created_at_ms
    )
    SELECT rotated_invitation.token_hash, 'invitation',
           rotated_invitation.normalized_email, '/organizations',
           jsonb_build_object('invitation_id', rotated_invitation.invitation_id::text),
           rotated_invitation.expires_at_ms, $12
    FROM rotated_invitation
    RETURNING token_hash
),
new_outbox AS (
    INSERT INTO auth_outbox (
        outbox_id, kind, deduplication_key, key_version,
        payload_ciphertext, status, available_at_ms, created_at_ms, updated_at_ms
    )
    SELECT $6::text::uuid, 'mail', $7, $8, $9,
           'pending', $12, $12, $12
    FROM new_token
    RETURNING outbox_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $10::text::uuid, rotated_invitation.organization_id,
           actor.user_id, actor.session_id,
           'member.invite.resend', 'invitation',
           rotated_invitation.invitation_id::text, 'succeeded',
           $11, jsonb_build_object('role_id', rotated_invitation.role_id), $12
    FROM rotated_invitation
    JOIN actor ON TRUE
    JOIN new_outbox ON TRUE
    RETURNING audit_id
)
SELECT rotated_invitation.invitation_id::text AS invitation_id,
       rotated_invitation.organization_id::text AS organization_id,
       rotated_invitation.normalized_email,
       rotated_invitation.role_id,
       rotated_invitation.status,
       rotated_invitation.expires_at_ms
FROM rotated_invitation
JOIN new_audit ON TRUE
