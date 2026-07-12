UPDATE auth_outbox
SET status = CASE WHEN attempt_count >= $6 THEN 'dead_letter' ELSE 'pending' END,
    available_at_ms = $4,
    lease_id = NULL,
    leased_until_ms = NULL,
    last_error_code = $5,
    updated_at_ms = $3
WHERE outbox_id = $1::text::uuid
  AND lease_id = $2::text::uuid
  AND status = 'leased'
RETURNING status AS outcome
