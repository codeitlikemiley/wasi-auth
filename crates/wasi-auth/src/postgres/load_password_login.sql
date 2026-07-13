SELECT
    users.user_id::text AS user_id,
    users.primary_email,
    users.status,
    users.security_revision,
    passwords.password_hash
FROM auth_users AS users
JOIN auth_passwords AS passwords ON passwords.user_id = users.user_id
WHERE users.normalized_email = $1
  AND passwords.revoked_at_ms IS NULL
LIMIT 1
