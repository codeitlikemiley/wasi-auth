WITH configured AS (
    SELECT
        value->>'kid' AS key_id,
        value->>'algorithm' AS algorithm,
        value->>'status' AS status,
        value->'public_jwk' AS public_jwk,
        COALESCE((value->>'has_private_material')::boolean, FALSE) AS has_private_material
    FROM jsonb_array_elements($1) value
),
retired_missing AS (
    UPDATE auth_signing_keys keys
    SET status = 'retired',
        activated_at_ms = NULL,
        retired_at_ms = $3
    WHERE keys.status IN ('active', 'next')
      AND NOT EXISTS (
          SELECT 1 FROM configured
          WHERE configured.key_id = keys.key_id
      )
    RETURNING keys.key_id
),
retirement_guard AS (
    SELECT count(*) AS retired_count FROM retired_missing
),
synced AS (
    INSERT INTO auth_signing_keys (
        key_id, algorithm, status, public_jwk, key_version,
        private_key_ciphertext, secret_reference,
        created_at_ms, activated_at_ms, retired_at_ms, revoked_at_ms
    )
    SELECT
        configured.key_id,
        configured.algorithm,
        configured.status,
        configured.public_jwk,
        $2,
        NULL,
        CASE WHEN configured.has_private_material
             THEN 'runtime-key-ring:' || configured.key_id
             ELSE NULL END,
        $3,
        CASE WHEN configured.status = 'active' THEN $3 ELSE NULL END,
        CASE WHEN configured.status = 'retired' THEN $3 ELSE NULL END,
        CASE WHEN configured.status = 'revoked' THEN $3 ELSE NULL END
    FROM configured, retirement_guard
    WHERE configured.key_id IS NOT NULL
      AND configured.algorithm IN ('ES256', 'HS256')
      AND configured.status IN ('next', 'active', 'retired', 'revoked')
      AND configured.public_jwk IS NOT NULL
      AND configured.has_private_material
    ON CONFLICT (key_id) DO UPDATE
    SET algorithm = EXCLUDED.algorithm,
        public_jwk = EXCLUDED.public_jwk,
        key_version = EXCLUDED.key_version,
        secret_reference = EXCLUDED.secret_reference
    RETURNING key_id
)
SELECT count(*)::bigint AS synced_count FROM synced
