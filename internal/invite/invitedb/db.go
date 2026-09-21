// Package invitedb binds the invite package to the database. SQL bindings are
// kept apart from the security logic so the logic is unit-tested without a
// database; these bindings are covered by the tagged integration suite.
package invitedb

import (
	"context"
	"time"

	"github.com/go-freya/freya/services/auth/internal/invite"
	"github.com/go-freya/freya/services/auth/internal/store"
	"github.com/jackc/pgx/v5"
)

// DBStore adapts the database to Store/Tx.
type DBStore struct{ St *store.Store }

func (d DBStore) Atomic(ctx context.Context, scope store.Scope, fn func(any) error) error {
	return d.St.Tx(ctx, scope, func(tx pgx.Tx) error { return fn(invite.Tx(dbTx{tx})) })
}

type dbTx struct{ tx pgx.Tx }

func (d dbTx) Tenant(ctx context.Context, tid string) (store.Tenant, error) {
	return store.GetTenant(ctx, d.tx, tid)
}
func (d dbTx) UserByEmail(ctx context.Context, tid, e string) (store.User, error) {
	return store.GetUserByEmail(ctx, d.tx, tid, e)
}
func (d dbTx) InsertUser(ctx context.Context, u store.User) error {
	return store.InsertUser(ctx, d.tx, u)
}
func (d dbTx) SetPasswordHash(ctx context.Context, tid, uid, h string) error {
	return store.SetPassword(ctx, d.tx, tid, uid, h)
}
func (d dbTx) UpdateUserStatus(ctx context.Context, tid, uid, st string) error {
	return store.UpdateUserStatus(ctx, d.tx, tid, uid, st)
}
func (d dbTx) InsertInvitation(ctx context.Context, i store.Invitation) error {
	return store.InsertInvitation(ctx, d.tx, i)
}
func (d dbTx) Invitation(ctx context.Context, tid, id string) (store.Invitation, error) {
	return store.GetInvitation(ctx, d.tx, tid, id)
}
func (d dbTx) InvitationByHash(ctx context.Context, h string) (store.Invitation, error) {
	return store.GetInvitationByTokenHash(ctx, d.tx, h)
}
func (d dbTx) RotateInvitation(ctx context.Context, tid, id, h string, exp time.Time) error {
	return store.RotateInvitationToken(ctx, d.tx, tid, id, h, exp)
}
func (d dbTx) MarkInvitationAccepted(ctx context.Context, id string) error {
	return store.MarkInvitationAccepted(ctx, d.tx, id)
}
func (d dbTx) RolesByID(ctx context.Context, tid string, ids []string) ([]store.Role, error) {
	out := make([]store.Role, 0, len(ids))
	for _, id := range ids {
		r, err := store.GetRole(ctx, d.tx, tid, id)
		if err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, nil
}
func (d dbTx) ReplaceBindings(ctx context.Context, tid, uid, by string, ids []string) error {
	return store.ReplaceRoleBindings(ctx, d.tx, tid, uid, by, ids)
}
func (d dbTx) Enqueue(ctx context.Context, it store.OutboxItem) error {
	return store.EnqueueOutbox(ctx, d.tx, it)
}

// Feature 004.
func (d dbTx) GetGroup(ctx context.Context, tid, id string) (store.Group, error) {
	return store.GetGroup(ctx, d.tx, tid, id)
}
func (d dbTx) AddGroupMembers(ctx context.Context, tid, gid, addedBy string, ids []string) (int, error) {
	return store.AddGroupMembers(ctx, d.tx, tid, gid, addedBy, ids)
}
func (d dbTx) Roles(ctx context.Context, tid, uid string) ([]string, error) {
	return store.EffectiveRoleSlugs(ctx, d.tx, tid, uid)
}
