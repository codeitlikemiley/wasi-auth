WITH bucket AS (
    INSERT INTO auth_rate_limit_buckets (
        bucket_key, attempt_count, window_expires_at_ms, updated_at_ms
    )
    VALUES ($1, 1, $4::bigint + $3::bigint, $4::bigint)
    ON CONFLICT (bucket_key) DO UPDATE
    SET attempt_count = CASE
            WHEN auth_rate_limit_buckets.window_expires_at_ms <= $4::bigint THEN 1
            ELSE auth_rate_limit_buckets.attempt_count + 1
        END,
        window_expires_at_ms = CASE
            WHEN auth_rate_limit_buckets.window_expires_at_ms <= $4::bigint
                THEN $4::bigint + $3::bigint
            ELSE auth_rate_limit_buckets.window_expires_at_ms
        END,
        updated_at_ms = $4::bigint
    RETURNING attempt_count, window_expires_at_ms
)
SELECT attempt_count <= $2::bigint AS allowed,
       GREATEST(window_expires_at_ms - $4::bigint, 0) AS retry_after_ms
FROM bucket
