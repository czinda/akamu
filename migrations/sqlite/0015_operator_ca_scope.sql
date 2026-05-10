-- Add ca_id to operators so that ca_ra and ca_operations accounts can be scoped to a single CA.
--
-- Empty string (default) = server-wide scope: the operator can act on any CA.
-- Non-empty = the operator is restricted to the named CA.
--
-- Meaningful for ca_ra (always scoped) and ca_operations (optionally scoped).
-- administrator and auditor are always server-wide.

ALTER TABLE operators ADD COLUMN ca_id TEXT NOT NULL DEFAULT '';
