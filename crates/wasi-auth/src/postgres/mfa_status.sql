WITH actor AS (
    SELECT sessions.user_id, sessions.assurance
    FROM auth_sessions AS sessions
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    WHERE sessions.session_id = $1::text::uuid
      AND sessions.revoked_at_ms IS NULL
      AND sessions.expires_at_ms > $2::bigint
      AND sessions.user_security_revision = users.security_revision
      AND users.status = 'active'
)
SELECT factors.enabled_at_ms IS NOT NULL AS totp_enrolled,
       actor.assurance,
       (SELECT count(*) FROM auth_recovery_codes AS recovery
        WHERE recovery.user_id = actor.user_id AND recovery.used_at_ms IS NULL) AS recovery_codes_remaining
FROM actor
LEFT JOIN auth_totp_factors AS factors ON factors.user_id = actor.user_id
