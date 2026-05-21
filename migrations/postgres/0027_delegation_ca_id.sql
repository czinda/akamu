-- Add ca_id to delegations so the field is preserved across DB restarts and gossip.
ALTER TABLE delegations ADD COLUMN ca_id TEXT NOT NULL DEFAULT '';
