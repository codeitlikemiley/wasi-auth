WITH eligible AS (
    SELECT sessions.session_id, sessions.user_id, memberships.organization_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    JOIN auth_memberships AS memberships
      ON memberships.user_id = sessions.user_id
     AND memberships.organization_id = $2::text::uuid
     AND memberships.status = 'active'
    JOIN auth_organizations AS organizations
      ON organizations.organization_id = memberships.organization_id
     AND organizations.status = 'active'
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $3
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
      -- Selecting a workspace only requires an active membership.
      -- Privileged mutations (invite, role change, org update, …) still
      -- enforce AAL2 on their own SQL paths.
    FOR UPDATE OF sessions
),
selected AS (
    UPDATE auth_sessions AS sessions
    SET selected_organization_id = eligible.organization_id,
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $3
    FROM eligible
    WHERE sessions.session_id = eligible.session_id
    RETURNING sessions.session_id, sessions.user_id, sessions.selected_organization_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $4::text::uuid, selected.selected_organization_id,
           selected.user_id, selected.session_id,
           'organization.select', 'session', selected.session_id::text, 'succeeded',
           $5, NULL, '{}', $3
    FROM selected
    RETURNING audit_id
)
SELECT
    'selected'::text AS outcome,
    selected.selected_organization_id::text AS organization_id
FROM selected
JOIN new_audit ON TRUE
