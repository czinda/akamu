-- Add ca_id to operators so that ca_ra accounts can be scoped to a single CA.
--
-- Empty string (default) = server-wide scope: the operator can act on any CA.
-- Non-empty = the operator is restricted to the named CA.
--
-- Only meaningful for the ca_ra role; administrator and ca_operations are
-- always server-wide.  The application layer enforces this invariant.

ALTER TABLE operators ADD COLUMN ca_id TEXT NOT NULL DEFAULT '';
