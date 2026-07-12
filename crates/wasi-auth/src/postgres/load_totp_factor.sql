SELECT factors.user_id::text AS user_id,
       factors.key_version,
       factors.secret_ciphertext,
       factors.enabled_at_ms
FROM auth_sessions AS sessions
JOIN auth_users AS users ON users.user_id = sessions.user_id
JOIN auth_totp_factors AS factors ON factors.user_id = sessions.user_id
WHERE sessions.session_id = $1::text::uuid
  AND sessions.revoked_at_ms IS NULL
  AND sessions.expires_at_ms > $2::bigint
  AND sessions.user_security_revision = users.security_revision
  AND users.status = 'active'
LIMIT 1
