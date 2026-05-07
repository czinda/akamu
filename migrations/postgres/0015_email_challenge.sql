-- no-transaction
-- RFC 8823 email-reply-00 challenge state
ALTER TABLE challenges ADD COLUMN email_token_part1 TEXT;
ALTER TABLE challenges ADD COLUMN email_message_id  TEXT;

-- Unique index; NULL values are not indexed (PostgreSQL NULL != NULL semantics).
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS idx_chall_email_message_id
    ON challenges(email_message_id)
    WHERE email_message_id IS NOT NULL;
