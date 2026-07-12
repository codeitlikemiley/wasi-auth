ALTER TABLE auth_outbox
    ALTER COLUMN key_version DROP NOT NULL,
    ALTER COLUMN payload_ciphertext DROP NOT NULL,
    ADD COLUMN relationship_operation TEXT,
    ADD COLUMN resource_type TEXT,
    ADD COLUMN resource_id TEXT,
    ADD COLUMN relation TEXT,
    ADD COLUMN subject_type TEXT,
    ADD COLUMN subject_id TEXT,
    ADD COLUMN resource_revision BIGINT;

UPDATE auth_outbox
SET status = 'dead_letter',
    last_error_code = 'legacy_relationship_payload',
    lease_id = NULL,
    leased_until_ms = NULL,
    updated_at_ms = GREATEST(updated_at_ms, available_at_ms)
WHERE kind = 'relationship';

INSERT INTO auth_outbox (
    outbox_id, kind, deduplication_key, key_version, payload_ciphertext,
    relationship_operation, resource_type, resource_id, relation,
    subject_type, subject_id, resource_revision,
    status, attempt_count, available_at_ms, created_at_ms, updated_at_ms
)
SELECT gen_random_uuid(),
       'relationship',
       concat(
           'relationship:organization:', memberships.organization_id::text,
           ':member:user:', memberships.user_id::text,
           ':', organizations.authorization_revision::text,
           ':bootstrap-grant'
       ),
       NULL, NULL,
       'grant', 'organization', memberships.organization_id::text, 'member',
       'user', memberships.user_id::text, organizations.authorization_revision,
       'pending', 0,
       GREATEST(memberships.updated_at_ms, organizations.updated_at_ms, users.updated_at_ms),
       GREATEST(memberships.updated_at_ms, organizations.updated_at_ms, users.updated_at_ms),
       GREATEST(memberships.updated_at_ms, organizations.updated_at_ms, users.updated_at_ms)
FROM auth_memberships AS memberships
JOIN auth_organizations AS organizations
  ON organizations.organization_id = memberships.organization_id
JOIN auth_users AS users ON users.user_id = memberships.user_id
WHERE memberships.status = 'active'
  AND organizations.status = 'active'
  AND users.status = 'active'
ON CONFLICT (deduplication_key) DO NOTHING;

ALTER TABLE auth_outbox
    ADD CONSTRAINT auth_outbox_payload_shape CHECK (
        (
            kind = 'mail'
            AND key_version IS NOT NULL
            AND payload_ciphertext IS NOT NULL
            AND relationship_operation IS NULL
            AND resource_type IS NULL
            AND resource_id IS NULL
            AND relation IS NULL
            AND subject_type IS NULL
            AND subject_id IS NULL
            AND resource_revision IS NULL
        )
        OR
        (
            kind = 'relationship'
            AND key_version IS NULL
            AND payload_ciphertext IS NULL
            AND relationship_operation IN ('grant', 'revoke')
            AND resource_type IS NOT NULL
            AND length(resource_type) BETWEEN 3 AND 64
            AND resource_id IS NOT NULL
            AND length(resource_id) BETWEEN 1 AND 1024
            AND relation IS NOT NULL
            AND length(relation) BETWEEN 3 AND 64
            AND subject_type IS NOT NULL
            AND length(subject_type) BETWEEN 3 AND 64
            AND subject_id IS NOT NULL
            AND length(subject_id) BETWEEN 1 AND 1024
            AND resource_revision IS NOT NULL
            AND resource_revision >= 1
        )
        OR
        (
            kind = 'relationship'
            AND status = 'dead_letter'
            AND last_error_code = 'legacy_relationship_payload'
            AND key_version IS NOT NULL
            AND payload_ciphertext IS NOT NULL
            AND relationship_operation IS NULL
            AND resource_type IS NULL
            AND resource_id IS NULL
            AND relation IS NULL
            AND subject_type IS NULL
            AND subject_id IS NULL
            AND resource_revision IS NULL
        )
    );

CREATE OR REPLACE FUNCTION auth_adjust_owner_count()
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

CREATE FUNCTION auth_track_membership_authorization()
RETURNS TRIGGER
LANGUAGE plpgsql
AS $$
DECLARE
    previous_active BOOLEAN := FALSE;
    current_active BOOLEAN := FALSE;
    target_organization UUID;
    target_user UUID;
    transition_at BIGINT;
    next_revision BIGINT;
    operation TEXT;
    intent_deduplication_key TEXT;
BEGIN
    IF TG_OP = 'DELETE' THEN
        previous_active := OLD.status = 'active';
        target_organization := OLD.organization_id;
        target_user := OLD.user_id;
        transition_at := OLD.updated_at_ms;
    ELSE
        current_active := NEW.status = 'active';
        target_organization := NEW.organization_id;
        target_user := NEW.user_id;
        transition_at := NEW.updated_at_ms;
    END IF;

    IF TG_OP = 'UPDATE' THEN
        previous_active := OLD.status = 'active';
        IF OLD.role_id IS NOT DISTINCT FROM NEW.role_id
           AND OLD.status IS NOT DISTINCT FROM NEW.status THEN
            RETURN NULL;
        END IF;
    END IF;

    UPDATE auth_organizations
    SET authorization_revision = authorization_revision + 1,
        updated_at_ms = GREATEST(updated_at_ms, transition_at)
    WHERE organization_id = target_organization
    RETURNING authorization_revision INTO next_revision;
    IF NOT FOUND THEN
        RAISE EXCEPTION 'membership references a missing organization'
            USING ERRCODE = '23503';
    END IF;

    IF previous_active = current_active THEN
        RETURN NULL;
    END IF;

    operation := CASE WHEN current_active THEN 'grant' ELSE 'revoke' END;
    intent_deduplication_key := concat(
        'relationship:organization:', target_organization::text,
        ':member:user:', target_user::text,
        ':', next_revision::text,
        ':', operation
    );
    INSERT INTO auth_outbox (
        outbox_id, kind, deduplication_key, key_version, payload_ciphertext,
        relationship_operation, resource_type, resource_id, relation,
        subject_type, subject_id, resource_revision,
        status, attempt_count, available_at_ms, created_at_ms, updated_at_ms
    ) VALUES (
        gen_random_uuid(), 'relationship', intent_deduplication_key, NULL, NULL,
        operation, 'organization', target_organization::text, 'member',
        'user', target_user::text, next_revision,
        'pending', 0, transition_at, transition_at, transition_at
    )
    ON CONFLICT (deduplication_key) DO NOTHING;
    RETURN NULL;
END;
$$;

CREATE TRIGGER auth_membership_authorization_revision
AFTER INSERT OR UPDATE OF role_id, status OR DELETE
ON auth_memberships
FOR EACH ROW
EXECUTE FUNCTION auth_track_membership_authorization();

CREATE INDEX auth_outbox_relationship_resource_idx
    ON auth_outbox (
        resource_type, resource_id, status, resource_revision DESC, updated_at_ms DESC
    )
    WHERE kind = 'relationship';
