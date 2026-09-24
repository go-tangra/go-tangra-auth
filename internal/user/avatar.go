package user

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"image"
	"image/color"
	"image/draw"
	"image/jpeg"
	"image/png"
	"io"
	"net/http"
	"sync"

	xdraw "golang.org/x/image/draw"
	"golang.org/x/image/webp"

	"github.com/go-tangra/go-tangra-auth/v4/internal/audit"
	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
	"github.com/go-tangra/go-tangra-auth/v4/internal/tenantctx"
)

// Avatar refusals (closed vocabulary; surfaced as validation_failed details).
var (
	ErrUnsupportedType    = errors.New("unsupported_type")
	ErrTooLarge           = errors.New("body_too_large")
	ErrTooLargeDimensions = errors.New("too_large_dimensions")
	ErrDecodeFailed       = errors.New("decode_failed")
)

// AvatarContentType is the only type ever stored or served.
const AvatarContentType = "image/jpeg"

// AvatarLimits bound the pipeline (config `profile`).
type AvatarLimits struct {
	MaxBytes    int64 // upload size
	MaxPixels   int64 // width×height gate before decoding
	Size        int   // stored square edge
	Concurrency int   // concurrent decodes per instance

	onDecode func() // test hook: called when a full decode starts
	sem      *semaphore
}

type semaphore struct {
	once sync.Once
	ch   chan struct{}
}

func (l *AvatarLimits) acquire() func() {
	if l.Concurrency <= 0 {
		return func() {}
	}
	if l.sem == nil {
		l.sem = &semaphore{}
	}
	l.sem.once.Do(func() { l.sem.ch = make(chan struct{}, l.Concurrency) })
	l.sem.ch <- struct{}{}
	return func() { <-l.sem.ch }
}

// NormaliseAvatar validates an upload by content and returns a square JPEG:
// sniff → dimension gate on the header → decode (png/jpeg/webp) → centre
// crop → resample → composite on white → encode. Nothing but pixels survives.
func NormaliseAvatar(r io.Reader, l AvatarLimits) ([]byte, error) {
	if l.MaxBytes <= 0 {
		l.MaxBytes = 2 << 20
	}
	if l.MaxPixels <= 0 {
		l.MaxPixels = 4096 * 4096
	}
	if l.Size <= 0 {
		l.Size = 512
	}
	raw, err := io.ReadAll(io.LimitReader(r, l.MaxBytes+1))
	if err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return nil, ErrTooLarge
		}
		return nil, ErrDecodeFailed
	}
	if int64(len(raw)) > l.MaxBytes {
		return nil, ErrTooLarge
	}
	switch http.DetectContentType(raw) {
	case "image/png", "image/jpeg", "image/webp":
	default:
		return nil, ErrUnsupportedType
	}
	// Only png, jpeg and webp decoders are registered in this binary, and the
	// sniff above already limited the input to those types.
	cfg, _, err := image.DecodeConfig(bytes.NewReader(raw))
	if err != nil {
		return nil, ErrDecodeFailed
	}
	if cfg.Width <= 0 || cfg.Height <= 0 || int64(cfg.Width)*int64(cfg.Height) > l.MaxPixels {
		return nil, ErrTooLargeDimensions
	}
	release := l.acquire()
	defer release()
	if l.onDecode != nil {
		l.onDecode()
	}
	src, _, err := image.Decode(bytes.NewReader(raw))
	if err != nil {
		return nil, ErrDecodeFailed
	}
	// Centre crop to a square.
	b := src.Bounds()
	side := min(b.Dx(), b.Dy())
	x0 := b.Min.X + (b.Dx()-side)/2
	y0 := b.Min.Y + (b.Dy()-side)/2
	crop := image.Rect(x0, y0, x0+side, y0+side)
	edge := min(side, l.Size)
	// Composite onto white while resampling: the destination starts white and
	// the scaler draws with Over.
	dst := image.NewRGBA(image.Rect(0, 0, edge, edge))
	draw.Draw(dst, dst.Bounds(), image.NewUniform(color.White), image.Point{}, draw.Src)
	xdraw.CatmullRom.Scale(dst, dst.Bounds(), src, crop, xdraw.Over, nil)
	var out bytes.Buffer
	_ = jpeg.Encode(&out, dst, &jpeg.Options{Quality: 85}) // a bytes.Buffer never fails
	return out.Bytes(), nil
}

// Decoders are registered by importing them; keep the references explicit so
// the dependency justification is visible here.
var _ = png.Decode
var _ = webp.Decode

// AvatarStore is the persistence used by Avatars.
type AvatarStore interface {
	User(ctx context.Context, tenantID, id string) (store.User, error)
	UserAnyTenant(ctx context.Context, id string) (store.User, error)
	UpsertAvatar(ctx context.Context, a store.Avatar) error
	DeleteAvatar(ctx context.Context, tenantID, userID string) error
	GetAvatar(ctx context.Context, tenantID, userID, id string) (store.Avatar, error)
}

// Avatars stores and serves normalised pictures.
type Avatars struct {
	st     AvatarStore
	audit  *audit.Writer
	limits AvatarLimits
}

// NewAvatars wires the service.
func NewAvatars(st AvatarStore, a *audit.Writer, l AvatarLimits) *Avatars {
	return &Avatars{st: st, audit: a, limits: l}
}

// Set replaces the target's avatar with the normalised upload and returns its URL.
func (a *Avatars) Set(ctx context.Context, actor tenantctx.Actor, uid string, r io.Reader) (string, error) {
	if !mayEdit(actor, uid) {
		a.emit(audit.Event{Type: audit.AvatarUpdated, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: ErrForbidden.Error(), SubjectKind: "user", SubjectID: uid})
		return "", ErrForbidden
	}
	if _, err := lookupInTenant(ctx, a.st, a.emit, actor, uid); err != nil {
		return "", err
	}
	data, err := NormaliseAvatar(r, a.limits)
	if err != nil {
		a.emit(audit.Event{Type: audit.AvatarUpdated, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "refused", Reason: err.Error(), SubjectKind: "user", SubjectID: uid})
		return "", err
	}
	sum := sha256.Sum256(data)
	id := hex.EncodeToString(sum[:])
	if err := a.st.UpsertAvatar(ctx, store.Avatar{ID: id, TenantID: actor.TenantID, UserID: uid, ContentType: AvatarContentType, Bytes: data}); err != nil {
		return "", err
	}
	a.emit(audit.Event{Type: audit.AvatarUpdated, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "user", SubjectID: uid, Details: map[string]any{"size": len(data)}})
	return tenantctx.AvatarURL(uid, &id), nil
}

// Remove deletes the target's avatar (idempotent).
func (a *Avatars) Remove(ctx context.Context, actor tenantctx.Actor, uid string) error {
	if !mayEdit(actor, uid) {
		return ErrForbidden
	}
	u, err := lookupInTenant(ctx, a.st, a.emit, actor, uid)
	if err != nil {
		return err
	}
	if u.AvatarID == nil {
		return nil
	}
	if err := a.st.DeleteAvatar(ctx, actor.TenantID, uid); err != nil {
		return err
	}
	a.emit(audit.Event{Type: audit.AvatarRemoved, TenantID: actor.TenantID, ActorKind: string(actor.Kind), ActorUserID: actor.UserID, Outcome: "ok", SubjectKind: "user", SubjectID: uid})
	return nil
}

// Get returns the bytes of (user, id) for any signed-in member of the same
// tenant; a stale id, a foreign user or an unknown user is not found.
func (a *Avatars) Get(ctx context.Context, actor tenantctx.Actor, uid, id string) (store.Avatar, error) {
	av, err := a.st.GetAvatar(ctx, actor.TenantID, uid, id)
	if err != nil {
		return store.Avatar{}, ErrNotFound
	}
	return av, nil
}

func (a *Avatars) emit(e audit.Event) {
	if a.audit != nil {
		_ = a.audit.Emit(e)
	}
}
