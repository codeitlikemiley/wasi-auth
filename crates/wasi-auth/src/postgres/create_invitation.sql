WITH actor AS (
    SELECT sessions.session_id, sessions.user_id,
           EXISTS (
               SELECT 1 FROM auth_role_permissions AS owner_permission
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
     AND permission.permission = 'member.invite'
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $14::bigint
      AND sessions.user_security_revision = users.security_revision
      AND sessions.assurance IN ('aal2', 'aal3')
      AND users.status = 'active'
),
assignable_role AS (
    SELECT roles.organization_id, roles.role_id
    FROM auth_roles AS roles
    JOIN actor ON TRUE
    WHERE roles.organization_id = $2::text::uuid
      AND roles.role_id = $4
      AND ($4 <> 'owner' OR actor.can_transfer_ownership)
),
revoked_previous AS (
    UPDATE auth_invitations AS invitations
    SET status = 'revoked', updated_at_ms = $14
    FROM assignable_role
    WHERE invitations.organization_id = assignable_role.organization_id
      AND invitations.normalized_email = $3
      AND invitations.status = 'pending'
    RETURNING invitations.invitation_id
),
revocation_barrier AS (
    SELECT count(*) AS revoked FROM revoked_previous
),
new_invitation AS (
    INSERT INTO auth_invitations (
        invitation_id, organization_id, normalized_email, role_id,
        token_hash, status, expires_at_ms, created_by, created_at_ms, updated_at_ms
    )
    SELECT $5::text::uuid, assignable_role.organization_id, $3,
           assignable_role.role_id, $6, 'pending', $7, actor.user_id, $14, $14
    FROM assignable_role JOIN actor ON TRUE CROSS JOIN revocation_barrier
    RETURNING invitation_id, organization_id, normalized_email, role_id, status, expires_at_ms
),
new_token AS (
    INSERT INTO auth_one_time_tokens (
        token_hash, purpose, subject_hint, redirect_uri, payload,
        expires_at_ms, created_at_ms
    )
    SELECT $6, 'invitation', new_invitation.normalized_email,
           '/organizations',
           jsonb_build_object('invitation_id', new_invitation.invitation_id::text),
           new_invitation.expires_at_ms, $14
    FROM new_invitation
    RETURNING token_hash
),
new_outbox AS (
    INSERT INTO auth_outbox (
        outbox_id, kind, deduplication_key, key_version,
        payload_ciphertext, status, available_at_ms, created_at_ms, updated_at_ms
    )
    SELECT $8::text::uuid, 'mail', $9, $10, $11,
           'pending', $14, $14, $14
    FROM new_token
    RETURNING outbox_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $12::text::uuid, new_invitation.organization_id,
           actor.user_id, actor.session_id,
           'member.invite', 'invitation', new_invitation.invitation_id::text,
           'succeeded', $13,
           jsonb_build_object('role_id', new_invitation.role_id), $14
    FROM new_invitation JOIN actor ON TRUE JOIN new_outbox ON TRUE
    RETURNING audit_id
)
SELECT new_invitation.invitation_id::text AS invitation_id,
       new_invitation.organization_id::text AS organization_id,
       new_invitation.normalized_email,
       new_invitation.role_id,
       new_invitation.status,
       new_invitation.expires_at_ms
FROM new_invitation JOIN new_audit ON TRUE
