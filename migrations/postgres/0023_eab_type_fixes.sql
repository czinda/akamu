-- Fix type mismatch: created_by_operator_id was added as INTEGER but operators.id is BIGSERIAL.
-- Add FK constraint linking eab_keys to operators with ON DELETE SET NULL.
-- Add CHECK constraint to enforce the allowed HMAC algorithm names.
ALTER TABLE eab_keys ALTER COLUMN created_by_operator_id TYPE BIGINT;

ALTER TABLE eab_keys
    ADD CONSTRAINT fk_eab_keys_operator
    FOREIGN KEY (created_by_operator_id)
    REFERENCES operators(id)
    ON DELETE SET NULL;

ALTER TABLE eab_keys
    ADD CONSTRAINT chk_eab_alg
    CHECK (alg IN ('sha256', 'sha384', 'sha512'));
