CREATE OR REPLACE FUNCTION auth_adjust_owner_count()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    old_is_owner BOOLEAN := FALSE;
    new_is_owner BOOLEAN := FALSE;
    target_organization UUID;
    transition_at BIGINT;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        old_is_owner := OLD.role_id = 'owner' AND OLD.status = 'active';
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_is_owner := NEW.role_id = 'owner' AND NEW.status = 'active';
        transition_at := NEW.updated_at_ms;
    ELSE
        transition_at := OLD.updated_at_ms;
    END IF;

    IF old_is_owner AND NOT new_is_owner THEN
        target_organization := OLD.organization_id;
        UPDATE auth_organizations
        SET owner_count = owner_count - 1,
            authorization_revision = authorization_revision + 1,
            updated_at_ms = GREATEST(updated_at_ms, transition_at)
        WHERE organization_id = target_organization
          AND owner_count > 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'active organization must retain an owner'
                USING ERRCODE = '23514', CONSTRAINT = 'auth_organization_requires_owner';
        END IF;
    ELSIF new_is_owner AND NOT old_is_owner THEN
        target_organization := NEW.organization_id;
        UPDATE auth_organizations
        SET owner_count = owner_count + 1,
            authorization_revision = authorization_revision + 1,
            updated_at_ms = GREATEST(updated_at_ms, transition_at)
        WHERE organization_id = target_organization;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'membership references a missing organization'
                USING ERRCODE = '23503';
        END IF;
    END IF;

    IF TG_OP = 'DELETE' THEN
        RETURN OLD;
    END IF;
    RETURN NEW;
END;
$$;

DO $$
BEGIN
    IF EXISTS (
        SELECT 1 FROM auth_organizations
        WHERE status = 'active' AND owner_count < 1
    ) THEN
        RAISE EXCEPTION 'existing active organization has no owner'
            USING ERRCODE = '23514', CONSTRAINT = 'auth_organization_requires_owner';
    END IF;
END;
$$;
