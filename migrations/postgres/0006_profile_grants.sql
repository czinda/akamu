-- Profile grants for per-account profile authorization.
-- NULL = no restriction (any profile may be requested).
-- A JSON array of profile IDs restricts the account to only those profiles
-- when require_account_grant is set on a profile.
ALTER TABLE accounts ADD COLUMN profile_grants TEXT;

-- Same grant column on EAB keys: when an admin provisions an EAB key with
-- profile_grants set, those grants are copied to the account at creation time.
ALTER TABLE eab_keys ADD COLUMN profile_grants TEXT;
