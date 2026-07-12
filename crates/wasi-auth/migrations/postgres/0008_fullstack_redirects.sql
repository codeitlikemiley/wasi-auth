INSERT INTO auth_application_redirects (redirect_path, created_at_ms)
VALUES
    ('/account/security', 0),
    ('/dashboard', 0)
ON CONFLICT (redirect_path) DO NOTHING;
