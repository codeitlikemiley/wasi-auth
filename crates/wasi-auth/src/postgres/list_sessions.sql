SELECT
    session_id::text AS session_id,
    selected_organization_id::text AS organization_id,
    assurance,
    created_at_ms,
    expires_at_ms
FROM auth_sessions
WHERE user_id = $1::text::uuid
  AND revoked_at_ms IS NULL
  AND expires_at_ms > $2
ORDER BY created_at_ms DESC, session_id
LIMIT 100
