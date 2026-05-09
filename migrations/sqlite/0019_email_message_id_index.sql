-- Unique index on email_message_id; duplicate webhook deliveries for the same
-- Message-ID are caught at the storage layer.  The partial form keeps the index
-- sparse: only rows with a non-NULL message ID are indexed.
CREATE UNIQUE INDEX IF NOT EXISTS idx_chall_email_message_id
    ON challenges(email_message_id)
    WHERE email_message_id IS NOT NULL;
