-- RFC 8823 email-reply-00 challenge state
ALTER TABLE challenges ADD COLUMN email_token_part1 TEXT;
ALTER TABLE challenges ADD COLUMN email_message_id  TEXT;

-- Sparse index: only rows with a message ID are indexed.
-- UNIQUE already creates an implicit index; the explicit partial form keeps it sparse.
CREATE UNIQUE INDEX IF NOT EXISTS idx_chall_email_message_id
    ON challenges(email_message_id)
    WHERE email_message_id IS NOT NULL;
