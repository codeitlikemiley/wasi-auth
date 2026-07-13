SELECT CASE
           WHEN actor_key = $2
            AND operation = 'register_password'
            AND request_hash = $3
           THEN 'replayed'
           ELSE 'idempotency_conflict'
       END AS outcome,
       CASE
           WHEN actor_key = $2
            AND operation = 'register_password'
            AND request_hash = $3
           THEN response_public ->> 'user_id'
           ELSE NULL
       END AS user_id
FROM auth_idempotency
WHERE idempotency_key = $1;
