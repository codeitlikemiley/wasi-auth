SELECT refresh_tokens.session_id::text AS session_id
FROM auth_refresh_tokens AS refresh_tokens
WHERE refresh_tokens.token_hash = $1
LIMIT 1
