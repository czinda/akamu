-- no-transaction
-- Unique index on email_message_id; duplicate webhook deliveries for the same
-- Message-ID are caught at the storage layer.  NULL values are not indexed
-- (PostgreSQL NULL != NULL semantics), so a partial index keeps it sparse.
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_chall_email_message_id
    ON challenges(email_message_id)
    WHERE email_message_id IS NOT NULL;
