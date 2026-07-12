SELECT
    users.user_id::text AS user_id,
    users.primary_email,
    passkeys.credential_id,
    passkeys.public_key_cose
FROM auth_users users
JOIN auth_passkeys passkeys ON passkeys.user_id = users.user_id
WHERE users.normalized_email = $1
  AND users.status = 'active'
ORDER BY passkeys.created_at_ms, passkeys.credential_id
