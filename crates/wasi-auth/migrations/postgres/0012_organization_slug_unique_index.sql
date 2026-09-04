CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS auth_organizations_slug_uidx
    ON public.auth_organizations (slug)
    WHERE slug IS NOT NULL;
