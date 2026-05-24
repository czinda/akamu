-- Add tkvalue column to store JWTClaimConstraints DER for encoder-backed identifiers.
-- Used at finalize time to retrieve the constraint blob from dns authzs validated via tkauth-01.
ALTER TABLE tkauth_jti_cache ADD COLUMN tkvalue TEXT;
