-- Kerberos principal that derived this EAB key via /acme/eab (HKDF derivation).
-- NULL for config-file keys and admin-provisioned keys (those use created_by_operator_id).
-- Used to link the key back to an operator for web UI EAB login.
ALTER TABLE eab_keys ADD COLUMN bound_principal TEXT, ALGORITHM=INSTANT;
