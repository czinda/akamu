-- Fix type mismatch: created_by_operator_id was added as INTEGER but operators.id is BIGINT.
-- Add FK constraint and CHECK constraint on alg in one ALTER TABLE to minimise table rebuilds.
-- Note: MariaDB 10.2.1+ enforces CHECK constraints; earlier versions accept but ignore them.
ALTER TABLE eab_keys
    MODIFY COLUMN created_by_operator_id BIGINT,
    ADD CONSTRAINT fk_eab_keys_operator
        FOREIGN KEY (created_by_operator_id)
        REFERENCES operators(id)
        ON DELETE SET NULL,
    ADD CONSTRAINT chk_eab_alg
        CHECK (alg IN ('sha256', 'sha384', 'sha512'));
