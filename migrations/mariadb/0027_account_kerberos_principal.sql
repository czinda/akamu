ALTER TABLE accounts ADD COLUMN kerberos_principal TEXT, ALGORITHM=INSTANT;
-- Kerberos principal stored at account registration time when the account
-- was created via a GSSAPI-authenticated EAB key (eab_keys.bound_principal).
-- NULL for accounts not using GSSAPI EAB.
