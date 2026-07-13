WITH actor AS (
    SELECT sessions.session_id, sessions.user_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    JOIN auth_system_administrators AS administrators
      ON administrators.user_id = sessions.user_id
     AND administrators.revoked_at_ms IS NULL
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $4::bigint
      AND sessions.user_security_revision = users.security_revision
      AND sessions.assurance IN ('aal2', 'aal3')
      AND users.status = 'active'
),
locked_organizations AS MATERIALIZED (
    SELECT organizations.organization_id, memberships.role_id, memberships.status
    FROM auth_organizations AS organizations
    JOIN auth_memberships AS memberships
      ON memberships.organization_id = organizations.organization_id
     AND memberships.user_id = $2::text::uuid
     AND memberships.status IN ('active', 'blocked')
    JOIN actor ON TRUE
    ORDER BY organizations.organization_id
    FOR UPDATE OF organizations
),
owner_guard AS (
    SELECT COALESCE(bool_and(
        target.role_id <> 'owner'
        OR target.status <> 'active'
        OR (SELECT count(*) FROM auth_memberships AS owners
            WHERE owners.organization_id = target.organization_id
              AND owners.role_id = 'owner'
              AND owners.status = 'active') > 1
    ), TRUE) AS may_disable
    FROM auth_memberships AS target
    JOIN locked_organizations
      ON locked_organizations.organization_id = target.organization_id
    WHERE target.user_id = $2::text::uuid
),
updated_user AS (
    UPDATE auth_users AS users
    SET status = CASE WHEN $3 THEN 'disabled' ELSE 'active' END,
        security_revision = users.security_revision + 1,
        updated_at_ms = $4
    FROM actor CROSS JOIN owner_guard
    WHERE users.user_id = $2::text::uuid
      AND users.status <> 'anonymized'
      AND (NOT $3 OR owner_guard.may_disable)
    RETURNING users.user_id, users.primary_email, users.status,
              users.created_at_ms, users.security_revision
),
updated_memberships AS (
    UPDATE auth_memberships AS memberships
    SET status = CASE
            WHEN $3 AND memberships.status = 'active' THEN 'blocked'
            WHEN NOT $3 AND memberships.status = 'blocked' THEN 'active'
            ELSE memberships.status
        END,
        updated_at_ms = $4
    FROM updated_user
    WHERE memberships.user_id = updated_user.user_id
      AND memberships.status IN ('active', 'blocked')
    RETURNING memberships.organization_id
),
revoked_sessions AS (
    UPDATE auth_sessions AS sessions
    SET revoked_at_ms = CASE WHEN $3 THEN $4 ELSE sessions.revoked_at_ms END,
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $4
    FROM updated_user
    WHERE sessions.user_id = updated_user.user_id
      AND ($3 OR sessions.revoked_at_ms IS NULL)
    RETURNING sessions.session_id
),
mutation_barrier AS (
    SELECT (SELECT count(*) FROM updated_memberships) AS memberships,
           (SELECT count(*) FROM revoked_sessions) AS sessions
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, actor_user_id, session_id, action, resource_type,
        resource_id, outcome, request_id, metadata, occurred_at_ms
    )
    SELECT $5::text::uuid, actor.user_id, actor.session_id,
           CASE WHEN $3 THEN 'system.user.disable' ELSE 'system.user.enable' END,
           'user', updated_user.user_id::text, 'succeeded', $6, '{}', $4
    FROM updated_user JOIN actor ON TRUE
    CROSS JOIN mutation_barrier
    RETURNING audit_id
)
SELECT updated_user.user_id::text AS user_id,
       updated_user.primary_email,
       updated_user.status,
       updated_user.created_at_ms
FROM updated_user JOIN new_audit ON TRUE
