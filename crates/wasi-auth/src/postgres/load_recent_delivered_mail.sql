SELECT deduplication_key,
       key_version,
       payload_ciphertext
FROM auth_outbox
WHERE kind = 'mail'
  AND status = 'delivered'
ORDER BY delivered_at_ms DESC NULLS LAST,
         updated_at_ms DESC,
         outbox_id DESC
LIMIT 100
