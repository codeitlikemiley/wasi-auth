ALTER TABLE auth_organizations
    ADD COLUMN owner_count BIGINT NOT NULL DEFAULT 0 CHECK (owner_count >= 0);

UPDATE auth_organizations AS organizations
SET owner_count = (
    SELECT count(*)
    FROM auth_memberships AS memberships
    WHERE memberships.organization_id = organizations.organization_id
      AND memberships.role_id = 'owner'
      AND memberships.status = 'active'
);

CREATE FUNCTION auth_adjust_owner_count()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    old_is_owner BOOLEAN := FALSE;
    new_is_owner BOOLEAN := FALSE;
    target_organization UUID;
BEGIN
    IF TG_OP <> 'INSERT' THEN
        old_is_owner := OLD.role_id = 'owner' AND OLD.status = 'active';
    END IF;
    IF TG_OP <> 'DELETE' THEN
        new_is_owner := NEW.role_id = 'owner' AND NEW.status = 'active';
    END IF;

    IF old_is_owner AND NOT new_is_owner THEN
        target_organization := OLD.organization_id;
        UPDATE auth_organizations
        SET owner_count = owner_count - 1
        WHERE organization_id = target_organization
          AND owner_count > 1;
        IF NOT FOUND THEN
            RAISE EXCEPTION 'active organization must retain an owner'
                USING ERRCODE = '23514', CONSTRAINT = 'auth_organization_requires_owner';
        END IF;
    ELSIF new_is_owner AND NOT old_is_owner THEN
        target_organization := NEW.organization_id;
        UPDATE auth_organizations
        SET owner_count = owner_count + 1
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

CREATE TRIGGER auth_membership_owner_count
BEFORE INSERT OR UPDATE OF role_id, status OR DELETE
ON auth_memberships
FOR EACH ROW
EXECUTE FUNCTION auth_adjust_owner_count();

CREATE FUNCTION auth_validate_owner_count()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF EXISTS (
        SELECT 1
        FROM auth_organizations
        WHERE organization_id = NEW.organization_id
          AND status = 'active'
          AND owner_count < 1
    ) THEN
        RAISE EXCEPTION 'active organization must have at least one owner'
            USING ERRCODE = '23514', CONSTRAINT = 'auth_organization_requires_owner';
    END IF;
    RETURN NULL;
END;
$$;

CREATE CONSTRAINT TRIGGER auth_organization_owner_invariant
AFTER INSERT OR UPDATE OF owner_count, status
ON auth_organizations
DEFERRABLE INITIALLY DEFERRED
FOR EACH ROW
EXECUTE FUNCTION auth_validate_owner_count();
