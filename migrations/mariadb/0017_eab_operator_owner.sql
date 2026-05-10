-- Track which operator provisioned each EAB key so that the key can be used
-- for web UI login with the same role as the provisioning operator.
-- NULL = key was provisioned from config file or before this migration.
ALTER TABLE eab_keys ADD COLUMN created_by_operator_id INTEGER, ALGORITHM=INSTANT;
