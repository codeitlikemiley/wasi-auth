WITH candidates AS MATERIALIZED (
    SELECT candidate.outbox_id
    FROM auth_outbox AS candidate
    WHERE candidate.kind = $1
      AND candidate.available_at_ms <= $2
      AND (
          candidate.status = 'pending'
          OR (candidate.status = 'leased' AND candidate.leased_until_ms <= $2)
      )
      AND (
          candidate.kind <> 'relationship'
          OR NOT EXISTS (
              SELECT 1
              FROM auth_outbox AS earlier
              WHERE earlier.kind = 'relationship'
                AND earlier.resource_type = candidate.resource_type
                AND earlier.resource_id = candidate.resource_id
                AND earlier.relation = candidate.relation
                AND earlier.subject_type = candidate.subject_type
                AND earlier.subject_id = candidate.subject_id
                AND earlier.status <> 'delivered'
                AND (
                    earlier.resource_revision < candidate.resource_revision
                    OR (
                        earlier.resource_revision = candidate.resource_revision
                        AND earlier.outbox_id < candidate.outbox_id
                    )
                )
          )
      )
    ORDER BY candidate.available_at_ms, candidate.created_at_ms, candidate.outbox_id
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
    outbox.relationship_operation,
    outbox.resource_type,
    outbox.resource_id,
    outbox.relation,
    outbox.subject_type,
    outbox.subject_id,
    outbox.resource_revision,
    outbox.attempt_count,
    outbox.lease_id::text AS lease_id,
    outbox.leased_until_ms
