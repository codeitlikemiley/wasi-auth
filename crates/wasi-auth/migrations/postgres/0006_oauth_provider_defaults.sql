CREATE TABLE auth_application_redirects (
    redirect_path TEXT PRIMARY KEY,
    created_at_ms BIGINT NOT NULL,
    CHECK (
        redirect_path LIKE '/%'
        AND redirect_path NOT LIKE '//%'
        AND length(redirect_path) <= 2048
    )
);

INSERT INTO auth_application_redirects (redirect_path, created_at_ms)
VALUES
    ('/', 0),
    ('/account', 0),
    ('/admin', 0),
    ('/organizations', 0)
ON CONFLICT (redirect_path) DO NOTHING;

INSERT INTO auth_provider_configs (
    provider_id, display_name, enabled, secret_reference,
    scopes, claim_mapping, created_at_ms, updated_at_ms
)
VALUES
    ('apple', 'Apple', FALSE, NULL, '["openid","email","name"]'::jsonb, '{}'::jsonb, 0, 0),
    ('facebook', 'Facebook', FALSE, NULL, '["email","public_profile"]'::jsonb, '{}'::jsonb, 0, 0),
    ('google', 'Google', FALSE, NULL, '["openid","email","profile"]'::jsonb, '{}'::jsonb, 0, 0)
ON CONFLICT (provider_id) DO NOTHING;
