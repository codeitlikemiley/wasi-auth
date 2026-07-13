SELECT
    users.user_id::text AS user_id,
    users.status,
    passwords.password_hash
FROM auth_users AS users
JOIN auth_passwords AS passwords ON passwords.user_id = users.user_id
WHERE users.user_id = $1::text::uuid
  AND passwords.revoked_at_ms IS NULL
LIMIT 1
