SELECT
    policy_revision,
    encode(checksum, 'hex') AS checksum_hex,
    status,
    created_by::text AS created_by,
    created_at_ms,
    activated_at_ms
FROM auth_policy_bundles
ORDER BY created_at_ms DESC, policy_revision DESC
LIMIT $1
