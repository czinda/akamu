-- Unique index on email_message_id; duplicate webhook deliveries for the same
-- Message-ID are caught at the storage layer.  InnoDB B-tree indexes permit
-- multiple NULL values under UNIQUE (NULL != NULL semantics), so no partial-index
-- syntax is needed.  Prefix length 255 is required for TEXT columns in all
-- InnoDB row formats.
CREATE UNIQUE INDEX IF NOT EXISTS idx_chall_email_message_id
    ON challenges(email_message_id(255));
