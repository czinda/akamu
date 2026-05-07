-- RFC 8823 email-reply-00 challenge state
ALTER TABLE challenges ADD COLUMN email_token_part1 TEXT;
ALTER TABLE challenges ADD COLUMN email_message_id  TEXT;

-- InnoDB does not store NULLs in B-tree indexes, so a plain index is sparse by default.
CREATE UNIQUE INDEX idx_chall_email_message_id ON challenges(email_message_id);
