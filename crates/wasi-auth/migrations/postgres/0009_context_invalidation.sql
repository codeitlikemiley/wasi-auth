CREATE OR REPLACE FUNCTION auth_notify_context_invalidation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    PERFORM pg_notify('wasi_auth_context_invalidation', 'changed');
    RETURN NULL;
END;
$$;

DROP TRIGGER IF EXISTS auth_users_context_invalidation ON auth_users;
CREATE TRIGGER auth_users_context_invalidation
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON auth_users
FOR EACH STATEMENT EXECUTE FUNCTION auth_notify_context_invalidation();

DROP TRIGGER IF EXISTS auth_sessions_context_invalidation ON auth_sessions;
CREATE TRIGGER auth_sessions_context_invalidation
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON auth_sessions
FOR EACH STATEMENT EXECUTE FUNCTION auth_notify_context_invalidation();

DROP TRIGGER IF EXISTS auth_organizations_context_invalidation ON auth_organizations;
CREATE TRIGGER auth_organizations_context_invalidation
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON auth_organizations
FOR EACH STATEMENT EXECUTE FUNCTION auth_notify_context_invalidation();

DROP TRIGGER IF EXISTS auth_memberships_context_invalidation ON auth_memberships;
CREATE TRIGGER auth_memberships_context_invalidation
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON auth_memberships
FOR EACH STATEMENT EXECUTE FUNCTION auth_notify_context_invalidation();

DROP TRIGGER IF EXISTS auth_role_permissions_context_invalidation ON auth_role_permissions;
CREATE TRIGGER auth_role_permissions_context_invalidation
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON auth_role_permissions
FOR EACH STATEMENT EXECUTE FUNCTION auth_notify_context_invalidation();

DROP TRIGGER IF EXISTS auth_policy_bundles_context_invalidation ON auth_policy_bundles;
CREATE TRIGGER auth_policy_bundles_context_invalidation
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON auth_policy_bundles
FOR EACH STATEMENT EXECUTE FUNCTION auth_notify_context_invalidation();

DROP TRIGGER IF EXISTS auth_system_administrators_context_invalidation ON auth_system_administrators;
CREATE TRIGGER auth_system_administrators_context_invalidation
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON auth_system_administrators
FOR EACH STATEMENT EXECUTE FUNCTION auth_notify_context_invalidation();

DROP TRIGGER IF EXISTS auth_signing_keys_context_invalidation ON auth_signing_keys;
CREATE TRIGGER auth_signing_keys_context_invalidation
AFTER INSERT OR UPDATE OR DELETE OR TRUNCATE ON auth_signing_keys
FOR EACH STATEMENT EXECUTE FUNCTION auth_notify_context_invalidation();
