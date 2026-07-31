-- Make authorizations.order_id nullable: RFC 8555 §7.4.1 standalone
-- pre-authorizations (POST /acme/new-authz) are not linked to any order, but
-- the original schema declared order_id NOT NULL, so every pre-authorization
-- request failed with a NOT NULL constraint violation.
ALTER TABLE authorizations ALTER COLUMN order_id DROP NOT NULL;
