WITH candidates AS MATERIALIZED (
    SELECT outbox_id
    FROM auth_outbox
    WHERE kind = $1
      AND available_at_ms <= $2
      AND (
          status = 'pending'
          OR (status = 'leased' AND leased_until_ms <= $2)
      )
    ORDER BY available_at_ms, created_at_ms, outbox_id
    FOR UPDATE SKIP LOCKED
    LIMIT $3
)
UPDATE auth_outbox AS outbox
SET status = 'leased',
    lease_id = $4::text::uuid,
    leased_until_ms = $5,
    attempt_count = outbox.attempt_count + 1,
    updated_at_ms = $2
FROM candidates
WHERE outbox.outbox_id = candidates.outbox_id
RETURNING
    outbox.outbox_id::text AS outbox_id,
    outbox.kind,
    outbox.deduplication_key,
    outbox.key_version,
    outbox.payload_ciphertext,
    outbox.attempt_count,
    outbox.lease_id::text AS lease_id,
    outbox.leased_until_ms
