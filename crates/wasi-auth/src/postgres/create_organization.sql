WITH existing_idempotency AS (
    SELECT operation, actor_key, request_hash, response_public
    FROM auth_idempotency
    WHERE idempotency_key = $1
),
idempotency_conflict AS (
    SELECT 1
    FROM existing_idempotency
    WHERE operation <> 'create_organization'
       OR actor_key <> $2
       OR request_hash <> $3
),
eligible AS (
    SELECT sessions.session_id, sessions.user_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    WHERE sessions.session_id = $6::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $9
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
      AND NOT EXISTS (SELECT 1 FROM existing_idempotency)
      AND NOT EXISTS (SELECT 1 FROM idempotency_conflict)
    FOR UPDATE OF sessions, users
),
new_organization AS (
    INSERT INTO auth_organizations (
        organization_id, name, status, authorization_revision,
        created_by, created_at_ms, updated_at_ms
    )
    SELECT $4::text::uuid, $5, 'active', 1, eligible.user_id, $9, $9
    FROM eligible
    RETURNING organization_id, name, status, created_by, created_at_ms
),
new_roles AS (
    INSERT INTO auth_roles (
        organization_id, role_id, name, built_in, created_at_ms, updated_at_ms
    )
    SELECT new_organization.organization_id, roles.role_id, roles.name, TRUE, $9, $9
    FROM new_organization
    CROSS JOIN (VALUES
        ('owner', 'Owner'),
        ('admin', 'Administrator'),
        ('member', 'Member'),
        ('viewer', 'Viewer')
    ) AS roles(role_id, name)
    RETURNING organization_id, role_id
),
new_permissions AS (
    INSERT INTO auth_role_permissions (organization_id, role_id, permission)
    SELECT new_roles.organization_id, permissions.role_id, permissions.permission
    FROM new_roles
    JOIN (VALUES
        ('owner', 'organization.view'),
        ('owner', 'organization.update'),
        ('owner', 'member.view'),
        ('owner', 'member.invite'),
        ('owner', 'member.manage'),
        ('owner', 'role.view'),
        ('owner', 'role.manage'),
        ('owner', 'audit.view'),
        ('owner', 'counter.view'),
        ('owner', 'counter.change'),
        ('owner', 'counter.reset'),
        ('owner', 'ownership.transfer'),
        ('admin', 'organization.view'),
        ('admin', 'organization.update'),
        ('admin', 'member.view'),
        ('admin', 'member.invite'),
        ('admin', 'member.manage'),
        ('admin', 'role.view'),
        ('admin', 'role.manage'),
        ('admin', 'audit.view'),
        ('admin', 'counter.view'),
        ('admin', 'counter.change'),
        ('admin', 'counter.reset'),
        ('member', 'organization.view'),
        ('member', 'member.view'),
        ('member', 'role.view'),
        ('member', 'counter.view'),
        ('member', 'counter.change'),
        ('viewer', 'organization.view'),
        ('viewer', 'member.view'),
        ('viewer', 'role.view'),
        ('viewer', 'counter.view')
    ) AS permissions(role_id, permission)
      ON permissions.role_id = new_roles.role_id
    RETURNING organization_id, role_id, permission
),
new_membership AS (
    INSERT INTO auth_memberships (
        organization_id, user_id, role_id, status, joined_at_ms, updated_at_ms
    )
    SELECT DISTINCT new_organization.organization_id, new_organization.created_by,
           'owner', 'active', $9, $9
    FROM new_organization
    JOIN new_permissions
      ON new_permissions.organization_id = new_organization.organization_id
     AND new_permissions.role_id = 'owner'
    RETURNING organization_id, user_id, role_id
),
selected_session AS (
    UPDATE auth_sessions AS sessions
    SET selected_organization_id = new_membership.organization_id,
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $9
    FROM new_membership
    WHERE sessions.session_id = $6::text::uuid
      AND sessions.user_id = new_membership.user_id
    RETURNING sessions.session_id, sessions.user_id, sessions.selected_organization_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $7::text::uuid, selected_session.selected_organization_id,
           selected_session.user_id, selected_session.session_id,
           'organization.create', 'organization',
           selected_session.selected_organization_id::text, 'succeeded',
           $8, NULL, '{}', $9
    FROM selected_session
    RETURNING audit_id
),
new_idempotency AS (
    INSERT INTO auth_idempotency (
        idempotency_key, actor_key, operation, request_hash,
        response_public, expires_at_ms, committed_at_ms
    )
    SELECT $1, $2, 'create_organization', $3,
           jsonb_build_object('organization_id', new_organization.organization_id::text),
           $10, $9
    FROM new_organization
    JOIN new_audit ON TRUE
    RETURNING response_public
),
created AS (
    SELECT
        'created'::text AS outcome,
        new_organization.organization_id,
        new_organization.name,
        new_organization.status,
        new_organization.created_at_ms
    FROM new_organization
    JOIN new_idempotency ON TRUE
),
replayed AS (
    SELECT
        'replayed'::text AS outcome,
        organizations.organization_id,
        organizations.name,
        organizations.status,
        organizations.created_at_ms
    FROM existing_idempotency
    JOIN auth_organizations AS organizations
      ON organizations.organization_id = (existing_idempotency.response_public->>'organization_id')::uuid
    JOIN auth_memberships AS memberships
      ON memberships.organization_id = organizations.organization_id
     AND memberships.status = 'active'
    JOIN auth_sessions AS replay_session
      ON replay_session.session_id = $2::text::uuid
     AND replay_session.user_id = memberships.user_id
    WHERE NOT EXISTS (SELECT 1 FROM idempotency_conflict)
),
created_output AS (
    SELECT
        created.outcome,
        created.organization_id::text AS organization_id,
        created.name,
        created.status,
        created.created_at_ms,
        'owner'::text AS role_id,
        jsonb_agg(new_permissions.permission ORDER BY new_permissions.permission) AS permissions
    FROM created
    JOIN new_permissions
      ON new_permissions.organization_id = created.organization_id
     AND new_permissions.role_id = 'owner'
    GROUP BY created.outcome, created.organization_id, created.name,
             created.status, created.created_at_ms
),
replayed_output AS (
    SELECT
        replayed.outcome,
        replayed.organization_id::text AS organization_id,
        replayed.name,
        replayed.status,
        replayed.created_at_ms,
        'owner'::text AS role_id,
        COALESCE(
            jsonb_agg(role_permissions.permission ORDER BY role_permissions.permission)
                FILTER (WHERE role_permissions.permission IS NOT NULL),
            '[]'::jsonb
        ) AS permissions
    FROM replayed
    LEFT JOIN auth_role_permissions AS role_permissions
      ON role_permissions.organization_id = replayed.organization_id
     AND role_permissions.role_id = 'owner'
    GROUP BY replayed.outcome, replayed.organization_id, replayed.name,
             replayed.status, replayed.created_at_ms
),
result AS (
    SELECT * FROM created_output
    UNION ALL
    SELECT * FROM replayed_output
)
SELECT * FROM result
UNION ALL
SELECT
    CASE
        WHEN EXISTS (SELECT 1 FROM idempotency_conflict) THEN 'idempotency_conflict'
        ELSE 'unauthorized'
    END,
    NULL, NULL, NULL, NULL, NULL, '[]'::jsonb
WHERE NOT EXISTS (SELECT 1 FROM result)
LIMIT 1
