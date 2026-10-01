-- +goose Up
-- Index-backed list sorting (go-tangra specs/032-server-side-tables perf.md):
-- with listquery v4.3.1, NotNull fields order without NULLS LAST, so a plain
-- btree ending in the tie-breaker serves both directions. The 0012 indexes
-- (users by lower(email) / created_at with id; audit by ts DESC, id DESC)
-- already match. A group's members page newest first by added_at with the
-- user_id tie-breaker; the primary key (group_id, user_id) and
-- group_members_tenant_user cannot deliver that order.
CREATE INDEX IF NOT EXISTS group_members_group_added ON group_members (tenant_id, group_id, added_at, user_id);
-- Each users-page row looks up the newest pending invitation of an invited
-- user (PageUsers' LATERAL, ORDER BY created_at DESC, id); invitations had
-- no index but the primary key and token_hash, so every row scanned and
-- sorted the table.
CREATE INDEX IF NOT EXISTS invitations_pending_email ON invitations (tenant_id, email, created_at DESC, id)
  WHERE accepted_at IS NULL AND revoked_at IS NULL;

-- +goose Down
DROP INDEX IF EXISTS invitations_pending_email;
DROP INDEX IF EXISTS group_members_group_added;
