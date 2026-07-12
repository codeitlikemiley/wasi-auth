SELECT
    users.user_id::text AS user_id,
    users.primary_email,
    passkeys.public_key_cose,
    passkeys.sign_count
FROM auth_passkeys passkeys
JOIN auth_users users ON users.user_id = passkeys.user_id
WHERE passkeys.user_id = $1::text::uuid
  AND passkeys.credential_id = $2
  AND users.status = 'active'
LIMIT 1
