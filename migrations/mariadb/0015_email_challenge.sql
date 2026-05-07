-- RFC 8823 email-reply-00 challenge state
ALTER TABLE challenges ADD COLUMN email_token_part1 TEXT,  ALGORITHM=INSTANT;
ALTER TABLE challenges ADD COLUMN email_message_id  TEXT,  ALGORITHM=INSTANT;

-- InnoDB B-tree indexes permit multiple NULL values under UNIQUE (NULL != NULL semantics),
-- so no partial-index syntax is needed; the index is already sparse over non-NULL values.
CREATE UNIQUE INDEX idx_chall_email_message_id ON challenges(email_message_id(255));
