package memstore

import (
	"context"
	"sort"
	"strings"
	"time"

	"github.com/go-freya/freya/services/auth/internal/store"
)

// Feature 004 state: groups, memberships, group roles, avatars. Kept in a
// separate file; the maps are lazily created so existing tests need no setup.

type groupState struct {
	groups  map[string]store.Group        // by id
	members map[string][]string           // group id → user ids (insertion order)
	added   map[string]time.Time          // group/user → added at
	roles   map[string][]string           // group id → role ids
	avatars map[string]store.Avatar       // user id → avatar
	profile map[string]store.ProfilePatch // unused placeholder for symmetry
}

func (m *Store) gs() *groupState {
	if m.g == nil {
		m.g = &groupState{groups: map[string]store.Group{}, members: map[string][]string{}, added: map[string]time.Time{}, roles: map[string][]string{}, avatars: map[string]store.Avatar{}, profile: map[string]store.ProfilePatch{}}
	}
	return m.g
}

func (m *Store) CreateGroup(_ context.Context, g store.Group) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	for _, x := range s.groups {
		if x.TenantID == g.TenantID && strings.EqualFold(x.Name, g.Name) {
			return store.ErrConflict
		}
	}
	g.CreatedAt, g.UpdatedAt = m.Now(), m.Now()
	s.groups[g.ID] = g
	return nil
}

func (m *Store) UpdateGroup(_ context.Context, tid, id, name, description string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	g, ok := s.groups[id]
	if !ok || g.TenantID != tid {
		return store.ErrNotFound
	}
	for _, x := range s.groups {
		if x.ID != id && x.TenantID == tid && strings.EqualFold(x.Name, name) {
			return store.ErrConflict
		}
	}
	g.Name, g.Description, g.UpdatedAt = name, description, m.Now()
	s.groups[id] = g
	return nil
}

func (m *Store) DeleteGroup(_ context.Context, tid, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	g, ok := s.groups[id]
	if !ok || g.TenantID != tid {
		return store.ErrNotFound
	}
	delete(s.groups, id)
	delete(s.members, id)
	delete(s.roles, id)
	return nil
}

func (m *Store) GetGroup(_ context.Context, tid, id string) (store.Group, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	g, ok := m.gs().groups[id]
	if !ok || g.TenantID != tid {
		return store.Group{}, store.ErrNotFound
	}
	return g, nil
}

func (m *Store) ListGroups(_ context.Context, tid, q string) ([]store.Group, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.Group
	for _, g := range m.gs().groups {
		if g.TenantID == tid && (q == "" || strings.Contains(strings.ToLower(g.Name), strings.ToLower(q))) {
			out = append(out, g)
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

func (m *Store) GroupMemberCounts(_ context.Context, tid string) (map[string]int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	out := map[string]int{}
	for id, g := range s.groups {
		if g.TenantID == tid {
			out[id] = len(s.members[id])
		}
	}
	return out, nil
}

func (m *Store) CountGroupMembers(_ context.Context, tid, gid string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	if g, ok := s.groups[gid]; !ok || g.TenantID != tid {
		return 0, store.ErrNotFound
	}
	return len(s.members[gid]), nil
}

func (m *Store) ListGroupMembers(_ context.Context, tid, gid string, after time.Time, limit int) ([]store.GroupMember, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	var out []store.GroupMember
	for _, uid := range s.members[gid] {
		at := s.added[gid+"/"+uid]
		if !at.After(after) {
			continue
		}
		_, u, _ := m.userByID(tid, uid)
		out = append(out, store.GroupMember{UserID: uid, Email: u.Email, DisplayName: u.DisplayName, Status: u.Status, AvatarID: u.AvatarID, AddedAt: at})
		if len(out) == limit {
			break
		}
	}
	return out, nil
}

func (m *Store) AddGroupMembers(_ context.Context, tid, gid, _ string, userIDs []string) (int, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	if g, ok := s.groups[gid]; !ok || g.TenantID != tid {
		return 0, store.ErrNotFound
	}
	added := 0
	for _, uid := range userIDs {
		if _, u, ok := m.userByID(tid, uid); !ok || u.Status == "imported" {
			return added, store.ErrNotFound
		}
		exists := false
		for _, x := range s.members[gid] {
			if x == uid {
				exists = true
			}
		}
		if exists {
			continue
		}
		s.members[gid] = append(s.members[gid], uid)
		s.added[gid+"/"+uid] = m.Now().Add(time.Duration(len(s.added)) * time.Microsecond)
		added++
	}
	return added, nil
}

func (m *Store) RemoveGroupMember(_ context.Context, tid, gid, uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	if g, ok := s.groups[gid]; !ok || g.TenantID != tid {
		return nil
	}
	var keep []string
	for _, x := range s.members[gid] {
		if x != uid {
			keep = append(keep, x)
		}
	}
	s.members[gid] = keep
	delete(s.added, gid+"/"+uid)
	return nil
}

func (m *Store) IsGroupMember(_ context.Context, tid, gid, uid string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	if g, ok := s.groups[gid]; !ok || g.TenantID != tid {
		return false, nil
	}
	for _, x := range s.members[gid] {
		if x == uid {
			return true, nil
		}
	}
	return false, nil
}

func (m *Store) UserGroups(_ context.Context, tid, uid string) ([]store.Group, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	var out []store.Group
	for gid, members := range s.members {
		g := s.groups[gid]
		if g.TenantID != tid {
			continue
		}
		for _, x := range members {
			if x == uid {
				out = append(out, g)
			}
		}
	}
	sort.Slice(out, func(i, j int) bool { return strings.ToLower(out[i].Name) < strings.ToLower(out[j].Name) })
	return out, nil
}

func (m *Store) ReplaceGroupRoles(_ context.Context, tid, gid, _ string, roleIDs []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	if g, ok := s.groups[gid]; !ok || g.TenantID != tid {
		return store.ErrNotFound
	}
	s.roles[gid] = append([]string(nil), roleIDs...)
	return nil
}

func (m *Store) GroupRoles(_ context.Context, tid, gid string) ([]store.Role, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	if g, ok := s.groups[gid]; !ok || g.TenantID != tid {
		return nil, store.ErrNotFound
	}
	var out []store.Role
	for _, id := range s.roles[gid] {
		if r, ok := m.RoleRows[id]; ok && r.TenantID == tid {
			out = append(out, r)
		}
	}
	return out, nil
}

func (m *Store) GroupRoleSlugs(_ context.Context, tid string) (map[string][]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	out := map[string][]string{}
	for gid, ids := range s.roles {
		if s.groups[gid].TenantID != tid {
			continue
		}
		for _, id := range ids {
			if r, ok := m.RoleRows[id]; ok {
				out[gid] = append(out[gid], r.Slug)
			}
		}
		sort.Strings(out[gid])
	}
	return out, nil
}

func (m *Store) EffectiveRoles(_ context.Context, tid, uid string) ([]store.EffectiveRoleRow, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	s := m.gs()
	var out []store.EffectiveRoleRow
	for _, id := range m.Bindings[tid+"/"+uid] {
		if r, ok := m.RoleRows[id]; ok && r.TenantID == tid {
			out = append(out, store.EffectiveRoleRow{RoleID: r.ID, Slug: r.Slug, Source: "direct"})
		}
	}
	for gid, members := range s.members {
		g := s.groups[gid]
		if g.TenantID != tid {
			continue
		}
		for _, x := range members {
			if x != uid {
				continue
			}
			for _, id := range s.roles[gid] {
				if r, ok := m.RoleRows[id]; ok {
					out = append(out, store.EffectiveRoleRow{RoleID: r.ID, Slug: r.Slug, Source: "group", GroupID: gid, GroupName: g.Name})
				}
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Slug != out[j].Slug {
			return out[i].Slug < out[j].Slug
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].GroupName < out[j].GroupName
	})
	return out, nil
}

// Roles (session/sign-in view) returns effective slugs: direct ∪ groups.
func (m *Store) effectiveSlugsLocked(tid, uid string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(slug string) {
		if !seen[slug] {
			seen[slug] = true
			out = append(out, slug)
		}
	}
	if ids, ok := m.Bindings[tid+"/"+uid]; ok {
		for _, id := range ids {
			if r, ok := m.RoleRows[id]; ok && r.TenantID == tid {
				add(r.Slug)
			}
		}
	} else {
		for _, s := range m.RoleMap[tid+"/"+uid] {
			add(s)
		}
	}
	if m.g != nil {
		for gid, members := range m.g.members {
			if m.g.groups[gid].TenantID != tid {
				continue
			}
			for _, x := range members {
				if x == uid {
					for _, id := range m.g.roles[gid] {
						if r, ok := m.RoleRows[id]; ok {
							add(r.Slug)
						}
					}
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------- profiles & avatars

func (m *Store) UpdateProfile(_ context.Context, tid, id string, p store.ProfilePatch) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, u, ok := m.userByID(tid, id)
	if !ok {
		return store.ErrNotFound
	}
	now := m.Now()
	u.FirstName, u.LastName, u.Phone, u.DisplayName, u.DisplayNameExplicit, u.ProfileUpdatedAt, u.UpdatedAt = p.FirstName, p.LastName, p.Phone, p.DisplayName, p.DisplayNameExplicit, &now, now
	m.Users[k] = u
	return nil
}

func (m *Store) LookupProfiles(_ context.Context, tid string, ids []string) ([]store.PublicProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var out []store.PublicProfile
	for _, id := range ids {
		if _, u, ok := m.userByID(tid, id); ok {
			out = append(out, store.PublicProfile{ID: u.ID, DisplayName: u.DisplayName, AvatarID: u.AvatarID})
		}
	}
	return out, nil
}

func (m *Store) ListActiveMemberIDs(_ context.Context, tid, after string, limit int, ids []string) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	want := map[string]bool{}
	for _, id := range ids {
		want[id] = true
	}
	var out []string
	for _, u := range m.Users {
		if u.TenantID != tid || u.Status != "active" {
			continue
		}
		if len(ids) > 0 && !want[u.ID] {
			continue
		}
		if len(ids) == 0 && u.ID <= after {
			continue
		}
		out = append(out, u.ID)
	}
	sort.Strings(out)
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Store) SearchProfiles(_ context.Context, tid, q string, limit int) ([]store.PublicProfile, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	lq := strings.ToLower(q)
	var out []store.PublicProfile
	for _, u := range m.Users {
		if u.TenantID != tid || u.Status != "active" {
			continue
		}
		if strings.Contains(strings.ToLower(u.DisplayName), lq) || strings.Contains(strings.ToLower(u.FirstName), lq) || strings.Contains(strings.ToLower(u.LastName), lq) || strings.Contains(strings.ToLower(u.Email), lq) {
			out = append(out, store.PublicProfile{ID: u.ID, DisplayName: u.DisplayName, AvatarID: u.AvatarID, Email: u.Email})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].DisplayName), strings.ToLower(out[j].DisplayName)
		if a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

func (m *Store) UpsertAvatar(_ context.Context, a store.Avatar) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	k, u, ok := m.userByID(a.TenantID, a.UserID)
	if !ok {
		return store.ErrNotFound
	}
	a.CreatedAt = m.Now()
	m.gs().avatars[a.UserID] = a
	id := a.ID
	now := m.Now()
	u.AvatarID, u.ProfileUpdatedAt = &id, &now
	m.Users[k] = u
	return nil
}

func (m *Store) DeleteAvatar(_ context.Context, tid, uid string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.gs().avatars, uid)
	if k, u, ok := m.userByID(tid, uid); ok {
		u.AvatarID = nil
		m.Users[k] = u
	}
	return nil
}

func (m *Store) GetAvatar(_ context.Context, tid, uid, id string) (store.Avatar, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.gs().avatars[uid]
	if !ok || a.TenantID != tid || a.ID != id {
		return store.Avatar{}, store.ErrNotFound
	}
	return a, nil
}
