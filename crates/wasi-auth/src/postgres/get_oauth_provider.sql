SELECT provider_id, display_name, enabled, scopes, claim_mapping
FROM auth_provider_configs
WHERE provider_id = $1
LIMIT 1
