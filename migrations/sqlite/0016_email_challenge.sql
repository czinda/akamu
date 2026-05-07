-- RFC 8823 email-reply-00 challenge state
ALTER TABLE challenges ADD COLUMN email_token_part1 TEXT;
ALTER TABLE challenges ADD COLUMN email_message_id  TEXT;
