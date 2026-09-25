-- +goose Up
-- Feature 017: outbox rows are retired instead of re-claimed forever. A
-- permanent failure or the last allowed attempt sets failed_at (the row is
-- then never claimed again) and keeps a short, scrubbed reason.
ALTER TABLE outbox ADD COLUMN failed_at  timestamptz;
ALTER TABLE outbox ADD COLUMN last_error text CHECK (char_length(last_error) <= 200);
DROP INDEX outbox_pending_idx;
CREATE INDEX outbox_pending_idx ON outbox (next_attempt_at)
  WHERE sent_at IS NULL AND failed_at IS NULL;

-- +goose Down
DROP INDEX outbox_pending_idx;
CREATE INDEX outbox_pending_idx ON outbox (next_attempt_at) WHERE sent_at IS NULL;
ALTER TABLE outbox DROP COLUMN last_error;
ALTER TABLE outbox DROP COLUMN failed_at;
