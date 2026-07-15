-- Rolling-compatible organization slug expansion.

ALTER TABLE auth_organizations
    ADD COLUMN slug TEXT;

CREATE FUNCTION auth_default_organization_slug(display_name TEXT, organization UUID)
RETURNS TEXT
LANGUAGE plpgsql
IMMUTABLE
STRICT
AS $$
DECLARE
    prefix TEXT;
BEGIN
    prefix := lower(regexp_replace(display_name, '[^a-zA-Z0-9]+', '-', 'g'));
    prefix := trim(both '-' from prefix);
    IF prefix = '' OR prefix !~ '^[a-z]' THEN
        prefix := 'org';
    END IF;
    prefix := trim(trailing '-' from left(prefix, 15));
    IF prefix = '' THEN
        prefix := 'org';
    END IF;
    RETURN prefix || '-' || replace(organization::text, '-', '');
END;
$$;

CREATE FUNCTION auth_fill_organization_slug()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
BEGIN
    IF NEW.slug IS NULL OR btrim(NEW.slug) = '' THEN
        NEW.slug := auth_default_organization_slug(NEW.name, NEW.organization_id);
    END IF;
    RETURN NEW;
END;
$$;

CREATE TRIGGER auth_organizations_fill_slug
BEFORE INSERT OR UPDATE OF slug ON auth_organizations
FOR EACH ROW
EXECUTE FUNCTION auth_fill_organization_slug();

ALTER TABLE auth_organizations
    ADD CONSTRAINT auth_organizations_slug_format
    CHECK (
        slug IS NULL
        OR (
            length(slug) BETWEEN 2 AND 48
            AND slug ~ '^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$'
        )
    ) NOT VALID;
