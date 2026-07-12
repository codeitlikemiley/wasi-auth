ALTER TABLE auth_invitations
    ADD COLUMN accepted_by UUID REFERENCES auth_users(user_id);

ALTER TABLE auth_audit_log
    ADD COLUMN sequence BIGINT GENERATED ALWAYS AS IDENTITY;

ALTER TABLE auth_audit_log
    ADD CONSTRAINT auth_audit_log_sequence_unique UNIQUE (sequence);

CREATE INDEX auth_audit_sequence_idx ON auth_audit_log (sequence);
CREATE INDEX auth_audit_org_sequence_idx
    ON auth_audit_log (organization_id, sequence);
