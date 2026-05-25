-- Add ca_flag column to store the atc.ca boolean from the authority token.
-- Used at finalize time to verify atc.ca matches the CSR's BasicConstraints cA field
-- per draft-ietf-acme-authority-token-jwtclaimcon §6 step 8.
ALTER TABLE tkauth_jti_cache ADD COLUMN ca_flag TINYINT(1) NOT NULL DEFAULT 0;
