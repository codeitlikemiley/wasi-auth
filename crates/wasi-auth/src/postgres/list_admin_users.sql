WITH actor AS (
    SELECT sessions.user_id
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    JOIN auth_system_administrators AS administrators
      ON administrators.user_id = sessions.user_id
     AND administrators.revoked_at_ms IS NULL
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $2::bigint
      AND sessions.user_security_revision = users.security_revision
      AND sessions.assurance IN ('aal2', 'aal3')
      AND users.status = 'active'
)
SELECT users.user_id::text AS user_id,
       users.primary_email,
       users.status,
       users.created_at_ms
FROM actor
JOIN auth_users AS users ON TRUE
ORDER BY users.created_at_ms DESC, users.user_id
