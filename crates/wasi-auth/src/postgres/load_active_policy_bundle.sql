SELECT
    policy_revision,
    cedar_schema,
    cedar_policy,
    entities
FROM auth_policy_bundles
WHERE status = 'active'
ORDER BY activated_at_ms DESC, policy_revision DESC
LIMIT 1
