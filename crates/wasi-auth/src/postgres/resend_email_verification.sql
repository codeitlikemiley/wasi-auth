WITH rate_bucket AS (
    INSERT INTO auth_rate_limit_buckets (
        bucket_key, attempt_count, window_expires_at_ms, updated_at_ms
    )
    VALUES ($12, 1, $11::bigint + 3600000, $11::bigint)
    ON CONFLICT (bucket_key) DO UPDATE
    SET attempt_count = CASE
            WHEN auth_rate_limit_buckets.window_expires_at_ms <= $11::bigint THEN 1
            ELSE auth_rate_limit_buckets.attempt_count + 1
        END,
        window_expires_at_ms = CASE
            WHEN auth_rate_limit_buckets.window_expires_at_ms <= $11::bigint THEN $11::bigint + 3600000
            ELSE auth_rate_limit_buckets.window_expires_at_ms
        END,
        updated_at_ms = $11::bigint
    RETURNING attempt_count
),
eligible AS (
    SELECT users.user_id, users.primary_email
    FROM auth_users AS users
    CROSS JOIN rate_bucket
    WHERE users.normalized_email = $1
      AND users.status = 'pending_verification'
      AND rate_bucket.attempt_count <= 5
),
invalidated AS (
    UPDATE auth_one_time_tokens AS tokens
    SET consumed_at_ms = $11
    FROM eligible
    WHERE tokens.user_id = eligible.user_id
      AND tokens.purpose = 'email_verification'
      AND tokens.consumed_at_ms IS NULL
    RETURNING tokens.user_id
),
invalidation_barrier AS (
    SELECT eligible.user_id, eligible.primary_email, count(invalidated.user_id) AS invalidated_count
    FROM eligible
    LEFT JOIN invalidated ON invalidated.user_id = eligible.user_id
    GROUP BY eligible.user_id, eligible.primary_email
),
new_token AS (
    INSERT INTO auth_one_time_tokens (
        token_hash, purpose, user_id, redirect_uri, payload,
        expires_at_ms, created_at_ms
    )
    SELECT $2, 'email_verification', user_id, $3,
           jsonb_build_object('user_id', user_id::text), $4, $11
    FROM invalidation_barrier
    RETURNING user_id
),
new_outbox AS (
    INSERT INTO auth_outbox (
        outbox_id, kind, deduplication_key, key_version,
        payload_ciphertext, status, available_at_ms,
        created_at_ms, updated_at_ms
    )
    SELECT $5::text::uuid, 'mail', $6, $7, $8, 'pending', $11, $11, $11
    FROM new_token
    RETURNING outbox_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $9::text::uuid, 'auth.email.verification.resend', 'user',
           new_token.user_id::text, 'succeeded', $10, '{}', $11
    FROM new_token
    JOIN new_outbox ON TRUE
    RETURNING audit_id
)
SELECT TRUE AS queued
FROM new_audit
