SELECT
    flow_id::text AS flow_id,
    user_id::text AS user_id,
    key_version,
    payload_ciphertext
FROM auth_flows
WHERE verifier_hash = $1
  AND kind = $2
  AND consumed_at_ms IS NULL
  AND expires_at_ms >= $3
LIMIT 1
