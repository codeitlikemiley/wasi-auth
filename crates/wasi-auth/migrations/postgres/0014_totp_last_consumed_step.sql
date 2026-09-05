ALTER TABLE auth_totp_factors
    ADD COLUMN last_consumed_step BIGINT;
