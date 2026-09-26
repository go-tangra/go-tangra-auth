package memstore

import (
	"context"
	"slices"
	"sort"
	"time"

	"github.com/go-tangra/go-tangra-auth/v4/internal/store"
)

// moduleState is the in-memory platform module catalogue (feature 019).
type moduleState struct {
	modules map[string]store.Module
	perms   map[string]store.ModulePermission // module/resource/action
	defs    map[string]store.ModuleRoleDef    // module/slug
	tenants map[string]store.TenantModule     // tenant/module
}

func (m *Store) ms() *moduleState {
	if m.mods == nil {
		m.mods = &moduleState{modules: map[string]store.Module{}, perms: map[string]store.ModulePermission{}, defs: map[string]store.ModuleRoleDef{}, tenants: map[string]store.TenantModule{}}
	}
	return m.mods
}

// UpsertModule mirrors store.UpsertModule.
func (m *Store) UpsertModule(_ context.Context, name, displayName string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpsertModule"); err != nil {
		return err
	}
	st := m.ms()
	now := m.Now()
	cur, ok := st.modules[name]
	switch {
	case !ok:
		if displayName == "" {
			displayName = name
		}
		cur = store.Module{Name: name, DisplayName: displayName, RegisteredAt: now}
	case displayName != "":
		cur.DisplayName = displayName
	}
	cur.UpdatedAt, cur.RetiredAt = now, nil
	st.modules[name] = cur
	return nil
}

// Modules lists the catalogue's modules by name.
func (m *Store) Modules(_ context.Context) ([]store.Module, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Module
	for _, x := range m.ms().modules {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// RetireModule mirrors store.RetireModule.
func (m *Store) RetireModule(_ context.Context, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.ms()
	mod, ok := st.modules[name]
	if !ok {
		return store.ErrNotFound
	}
	now := m.Now()
	if mod.RetiredAt == nil {
		mod.RetiredAt = &now
	}
	st.modules[name] = mod
	for k, p := range st.perms {
		if p.Module == name && p.RetiredAt == nil {
			p.RetiredAt = &now
			st.perms[k] = p
		}
	}
	for k, d := range st.defs {
		if d.Module == name && d.RetiredAt == nil {
			d.RetiredAt = &now
			st.defs[k] = d
		}
	}
	return nil
}

// UpsertModulePermission mirrors store.UpsertModulePermission.
func (m *Store) UpsertModulePermission(_ context.Context, p store.ModulePermission) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	p.RetiredAt = nil
	m.ms().perms[p.Module+"/"+p.Resource+"/"+p.Action] = p
	return nil
}

// ModulePermissions lists catalogue permissions of module ("" = all).
func (m *Store) ModulePermissions(_ context.Context, module string) ([]store.ModulePermission, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.ModulePermission
	for _, p := range m.ms().perms {
		if module == "" || p.Module == module {
			out = append(out, p)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		return a.Module+"/"+a.Resource+"/"+a.Action < b.Module+"/"+b.Resource+"/"+b.Action
	})
	return out, nil
}

// UpsertModuleRoleDef mirrors store.UpsertModuleRoleDef.
func (m *Store) UpsertModuleRoleDef(_ context.Context, d store.ModuleRoleDef) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.ms()
	k := d.Module + "/" + d.Slug
	cur, ok := st.defs[k]
	if ok && cur.DisplayName == d.DisplayName && cur.Description == d.Description && slices.Equal(cur.Permissions, d.Permissions) && cur.RetiredAt == nil {
		return false, nil
	}
	d.Permissions = append([]string(nil), d.Permissions...)
	d.UpdatedAt, d.RetiredAt = m.Now(), nil
	st.defs[k] = d
	return true, nil
}

// ModuleRoleDefs lists definitions of module ("" = all), retired included.
func (m *Store) ModuleRoleDefs(_ context.Context, module string) ([]store.ModuleRoleDef, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.ModuleRoleDef
	for _, d := range m.ms().defs {
		if module == "" || d.Module == module {
			d.Permissions = append([]string(nil), d.Permissions...)
			out = append(out, d)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Module+"/"+out[i].Slug < out[j].Module+"/"+out[j].Slug })
	return out, nil
}

// RetireModuleRoleDef mirrors store.RetireModuleRoleDef.
func (m *Store) RetireModuleRoleDef(_ context.Context, module, slug string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.ms()
	d, ok := st.defs[module+"/"+slug]
	if !ok {
		return store.ErrNotFound
	}
	if d.RetiredAt == nil {
		now := m.Now()
		d.RetiredAt = &now
	}
	st.defs[module+"/"+slug] = d
	return nil
}

// TenantModule mirrors store.GetTenantModule.
func (m *Store) TenantModule(_ context.Context, tid, module string) (store.TenantModule, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if tm, ok := m.ms().tenants[tid+"/"+module]; ok {
		return tm, nil
	}
	return store.TenantModule{}, store.ErrNotFound
}

// EnsureTenantModule mirrors store.EnsureTenantModule.
func (m *Store) EnsureTenantModule(_ context.Context, tid, module string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	st := m.ms()
	if _, ok := st.tenants[tid+"/"+module]; !ok {
		st.tenants[tid+"/"+module] = store.TenantModule{TenantID: tid, Module: module, FirstRegisteredAt: m.Now()}
	}
	return nil
}

// MarkLegacyMigrated mirrors store.MarkLegacyMigrated.
func (m *Store) MarkLegacyMigrated(_ context.Context, tid, module string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("MarkLegacyMigrated"); err != nil {
		return err
	}
	st := m.ms()
	tm, ok := st.tenants[tid+"/"+module]
	if !ok {
		return store.ErrNotFound
	}
	if tm.LegacyMigratedAt == nil {
		now := m.Now()
		tm.LegacyMigratedAt = &now
	}
	st.tenants[tid+"/"+module] = tm
	return nil
}

// AdoptBuiltinRole mirrors store.AdoptBuiltinRole.
func (m *Store) AdoptBuiltinRole(_ context.Context, tid, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.RoleRows[id]
	if !ok || r.TenantID != tid || r.OriginOf() != store.OriginCustom {
		return store.ErrNotFound
	}
	r.Builtin, r.Origin = true, store.OriginBuiltin
	m.RoleRows[id] = r
	return nil
}

// UpdateModuleRole mirrors store.UpdateModuleRole.
func (m *Store) UpdateModuleRole(_ context.Context, tid, id, name, description string, retiredAt *time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r, ok := m.RoleRows[id]
	if !ok || r.TenantID != tid || r.OriginOf() != store.OriginModule {
		return store.ErrNotFound
	}
	r.DisplayName, r.Description, r.RetiredAt = name, description, retiredAt
	m.RoleRows[id] = r
	return nil
}
