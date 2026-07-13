WITH created AS (
    INSERT INTO auth_flows (
        flow_id, kind, user_id, verifier_hash, key_version,
        payload_ciphertext, expires_at_ms, consumed_at_ms, created_at_ms
    )
    VALUES (
        $1::text::uuid, $2, $3::text::uuid, $4, $5,
        $6, $7, NULL, $8
    )
    RETURNING flow_id
)
SELECT 'created'::text AS outcome FROM created
