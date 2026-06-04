-- Audit events are now written to a systemd journal namespace instead of the
-- database.  Drop the table and its indexes.
DROP TABLE IF EXISTS audit_events;
