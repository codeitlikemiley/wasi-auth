ALTER TABLE auth_signing_keys
    DROP CONSTRAINT IF EXISTS auth_signing_keys_algorithm_check;

ALTER TABLE auth_signing_keys
    ADD CONSTRAINT auth_signing_keys_algorithm_check
    CHECK (algorithm IN ('ES256', 'HS256'));

ALTER TABLE auth_signing_keys
    ALTER COLUMN private_key_ciphertext DROP NOT NULL;

ALTER TABLE auth_signing_keys
    ADD COLUMN secret_reference TEXT;

ALTER TABLE auth_signing_keys
    ADD CONSTRAINT auth_signing_keys_material_check
    CHECK (private_key_ciphertext IS NOT NULL OR secret_reference IS NOT NULL);
