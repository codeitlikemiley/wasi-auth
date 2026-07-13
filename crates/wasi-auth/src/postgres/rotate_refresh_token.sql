WITH current_token AS (
    SELECT refresh_tokens.token_hash, refresh_tokens.session_id,
           refresh_tokens.family_id, refresh_tokens.expires_at_ms,
           refresh_tokens.rotated_at_ms, refresh_tokens.revoked_at_ms,
           refresh_tokens.successor_hash, refresh_tokens.successor_key_version,
           refresh_tokens.successor_ciphertext, refresh_tokens.replay_until_ms,
           sessions.user_id, sessions.expires_at_ms AS session_expires_at_ms,
           sessions.revoked_at_ms AS session_revoked_at_ms,
           users.status AS user_status,
           users.security_revision, sessions.user_security_revision
    FROM auth_refresh_tokens AS refresh_tokens
    JOIN auth_sessions AS sessions ON sessions.session_id = refresh_tokens.session_id
    JOIN auth_users AS users ON users.user_id = sessions.user_id
    WHERE refresh_tokens.token_hash = $1
      AND ($2::text IS NULL OR sessions.session_id = $2::text::uuid)
    FOR UPDATE OF refresh_tokens, sessions
),
rotatable AS (
    SELECT * FROM current_token
    WHERE rotated_at_ms IS NULL
      AND revoked_at_ms IS NULL
      AND expires_at_ms > $7::bigint
      AND session_revoked_at_ms IS NULL
      AND session_expires_at_ms > $7::bigint
      AND security_revision = user_security_revision
      AND user_status = 'active'
),
rotated AS (
    UPDATE auth_refresh_tokens AS refresh_tokens
    SET rotated_at_ms = $7,
        successor_hash = $3,
        successor_key_version = $4,
        successor_ciphertext = $5,
        replay_until_ms = $6
    FROM rotatable
    WHERE refresh_tokens.token_hash = rotatable.token_hash
    RETURNING refresh_tokens.session_id, refresh_tokens.family_id
),
next_token AS (
    INSERT INTO auth_refresh_tokens (
        token_hash, session_id, family_id, expires_at_ms, created_at_ms
    )
    SELECT $3, rotated.session_id, rotated.family_id, $8, $7
    FROM rotated
    RETURNING session_id, family_id
),
renewed_session AS (
    UPDATE auth_sessions AS sessions
    SET expires_at_ms = GREATEST(sessions.expires_at_ms, $12),
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $7
    FROM next_token
    WHERE sessions.session_id = next_token.session_id
      AND sessions.revoked_at_ms IS NULL
    RETURNING sessions.session_id
),
rotation_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, actor_user_id, session_id, action, resource_type,
        resource_id, outcome, request_id, metadata, occurred_at_ms
    )
    SELECT $9::text::uuid, current_token.user_id, next_token.session_id,
           'auth.token.refresh', 'session', next_token.session_id::text,
           'succeeded', $11,
           jsonb_build_object('family_id', next_token.family_id::text), $7
    FROM next_token
    JOIN renewed_session ON renewed_session.session_id = next_token.session_id
    JOIN current_token ON TRUE
    RETURNING audit_id
),
replayable AS (
    SELECT current_token.*
    FROM current_token
    WHERE current_token.rotated_at_ms IS NOT NULL
      AND current_token.revoked_at_ms IS NULL
      AND current_token.replay_until_ms >= $7::bigint
      AND current_token.successor_key_version IS NOT NULL
      AND current_token.successor_ciphertext IS NOT NULL
      AND current_token.session_revoked_at_ms IS NULL
      AND current_token.session_expires_at_ms > $7::bigint
      AND current_token.security_revision = current_token.user_security_revision
      AND current_token.user_status = 'active'
),
reuse AS (
    SELECT current_token.*
    FROM current_token
    WHERE current_token.rotated_at_ms IS NOT NULL
      AND current_token.revoked_at_ms IS NULL
      AND NOT EXISTS (SELECT 1 FROM replayable)
),
revoked_family AS (
    UPDATE auth_refresh_tokens AS refresh_tokens
    SET revoked_at_ms = $7
    FROM reuse
    WHERE refresh_tokens.family_id = reuse.family_id
      AND refresh_tokens.revoked_at_ms IS NULL
    RETURNING refresh_tokens.family_id
),
revoked_session AS (
    UPDATE auth_sessions AS sessions
    SET revoked_at_ms = $7,
        session_revision = sessions.session_revision + 1,
        updated_at_ms = $7
    FROM reuse
    WHERE sessions.session_id = reuse.session_id
      AND sessions.revoked_at_ms IS NULL
    RETURNING sessions.session_id
),
reuse_audit AS (
    INSERT INTO auth_audit_log (
        audit_id, actor_user_id, session_id, action, resource_type,
        resource_id, outcome, request_id, metadata, occurred_at_ms
    )
    SELECT $10::text::uuid, reuse.user_id, reuse.session_id,
           'auth.token.reuse', 'session', reuse.session_id::text,
           'failed', $11,
           jsonb_build_object(
               'family_id', reuse.family_id::text,
               'revoked_tokens', (SELECT count(*) FROM revoked_family)
           ), $7
    FROM reuse JOIN revoked_session ON TRUE
    RETURNING audit_id
)
SELECT 'rotated'::text AS outcome,
       $4::text AS response_key_version,
       $5::bytea AS response_ciphertext
FROM rotation_audit
UNION ALL
SELECT 'replayed'::text AS outcome,
       replayable.successor_key_version,
       replayable.successor_ciphertext
FROM replayable
UNION ALL
SELECT 'reuse_detected'::text AS outcome, NULL::text, NULL::bytea
FROM reuse_audit
UNION ALL
SELECT 'invalid'::text AS outcome, NULL::text, NULL::bytea
WHERE NOT EXISTS (SELECT 1 FROM rotation_audit)
  AND NOT EXISTS (SELECT 1 FROM replayable)
  AND NOT EXISTS (SELECT 1 FROM reuse_audit)
LIMIT 1
