WITH eligible AS (
    SELECT users.user_id, users.primary_email
    FROM auth_users AS users
    JOIN auth_passwords AS passwords ON passwords.user_id = users.user_id
    WHERE users.normalized_email = $1
      AND users.status = 'active'
      AND passwords.revoked_at_ms IS NULL
),
new_token AS (
    INSERT INTO auth_one_time_tokens (
        token_hash, purpose, user_id, subject_hint, redirect_uri,
        payload, expires_at_ms, consumed_at_ms, created_at_ms
    )
    SELECT $2, 'password_reset', eligible.user_id, $1, $3,
           '{}', $4, NULL, $11
    FROM eligible
    RETURNING user_id
),
new_outbox AS (
    INSERT INTO auth_outbox (
        outbox_id, kind, deduplication_key, key_version,
        payload_ciphertext, status, available_at_ms, created_at_ms, updated_at_ms
    )
    SELECT $5::text::uuid, 'mail', $6, $7, $8,
           'pending', $11, $11, $11
    FROM new_token
    RETURNING outbox_id
),
new_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, organization_id, actor_user_id, session_id,
        action, resource_type, resource_id, outcome,
        request_id, policy_revision, metadata, occurred_at_ms
    )
    SELECT $9::text::uuid, NULL, new_token.user_id, NULL,
           'auth.password.reset.start', 'user', new_token.user_id::text, 'succeeded',
           $10, NULL, '{}', $11
    FROM new_token
    JOIN new_outbox ON TRUE
    RETURNING audit_id
)
SELECT TRUE AS queued
FROM new_audit
