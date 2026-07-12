WITH existing_idempotency AS (
    SELECT response_public
    FROM auth_idempotency
    WHERE idempotency_key = $1
      AND actor_key = $2
      AND operation = 'register_password'
      AND request_hash = $3
),
conflicting_idempotency AS (
    SELECT 1
    FROM auth_idempotency
    WHERE idempotency_key = $1
      AND NOT (
          actor_key = $2
          AND operation = 'register_password'
          AND request_hash = $3
      )
),
new_user AS (
    INSERT INTO auth_users (
        user_id, normalized_email, primary_email, status,
        security_revision, created_at_ms, updated_at_ms
    )
    SELECT $4::text::uuid, $5, $6, 'pending_verification', 1, $18, $18
    WHERE NOT EXISTS (SELECT 1 FROM existing_idempotency)
      AND NOT EXISTS (SELECT 1 FROM conflicting_idempotency)
    ON CONFLICT (normalized_email) DO NOTHING
    RETURNING user_id
),
new_password AS (
    INSERT INTO auth_passwords (
        user_id, password_hash, created_at_ms, updated_at_ms
    )
    SELECT user_id, $7, $18, $18 FROM new_user
    RETURNING user_id
),
new_token AS (
    INSERT INTO auth_one_time_tokens (
        token_hash, purpose, user_id, redirect_uri, payload,
        expires_at_ms, created_at_ms
    )
    SELECT $8, 'email_verification', user_id, $9,
           jsonb_build_object('user_id', user_id::text), $10, $18
    FROM new_password
    RETURNING user_id
),
new_outbox AS (
    INSERT INTO auth_outbox (
        outbox_id, kind, deduplication_key, key_version,
        payload_ciphertext, status, available_at_ms,
        created_at_ms, updated_at_ms
    )
    SELECT $11::text::uuid, 'mail', $12, $13, $14, 'pending', $18, $18, $18
    FROM new_token
    RETURNING outbox_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, action, resource_type, resource_id, outcome,
        request_id, metadata, occurred_at_ms
    )
    SELECT $15::text::uuid, 'auth.password.register', 'user', new_user.user_id::text,
           'succeeded', $16, $17, $18
    FROM new_user CROSS JOIN new_outbox
    RETURNING resource_id
),
new_idempotency AS (
    INSERT INTO auth_idempotency (
        idempotency_key, actor_key, operation, request_hash,
        response_public, expires_at_ms, committed_at_ms
    )
    SELECT $1, $2, 'register_password', $3,
           jsonb_build_object('user_id', new_user.user_id::text), $19, $18
    FROM new_user CROSS JOIN new_audit
    RETURNING response_public
)
SELECT 'created'::text AS outcome,
       response_public ->> 'user_id' AS user_id
FROM new_idempotency
UNION ALL
SELECT 'replayed'::text AS outcome,
       response_public ->> 'user_id' AS user_id
FROM existing_idempotency
UNION ALL
SELECT 'idempotency_conflict'::text AS outcome, NULL::text AS user_id
WHERE EXISTS (SELECT 1 FROM conflicting_idempotency)
UNION ALL
SELECT 'email_conflict'::text AS outcome, NULL::text AS user_id
WHERE NOT EXISTS (SELECT 1 FROM existing_idempotency)
  AND NOT EXISTS (SELECT 1 FROM conflicting_idempotency)
  AND NOT EXISTS (SELECT 1 FROM new_user);
