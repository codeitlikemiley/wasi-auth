SELECT
    key_id,
    algorithm,
    status,
    public_jwk,
    key_version,
    secret_reference,
    created_at_ms,
    activated_at_ms,
    retired_at_ms,
    revoked_at_ms
FROM auth_signing_keys
ORDER BY created_at_ms, key_id
