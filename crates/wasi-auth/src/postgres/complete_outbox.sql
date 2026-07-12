UPDATE auth_outbox
SET status = 'delivered',
    delivered_at_ms = $3,
    delivery_id = $4,
    lease_id = NULL,
    leased_until_ms = NULL,
    last_error_code = NULL,
    updated_at_ms = $3
WHERE outbox_id = $1::text::uuid
  AND lease_id = $2::text::uuid
  AND status = 'leased'
RETURNING 'delivered'::text AS outcome
