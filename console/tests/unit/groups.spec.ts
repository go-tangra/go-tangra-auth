import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Groups from '@/views/admin/Groups.vue'
import GroupDetail from '@/views/admin/GroupDetail.vue'
import UserDetail from '@/views/admin/UserDetail.vue'
import { router } from '@/router'
import { useSession } from '@/stores/session'
import { click, mountView, q, stubFetch, type } from './helpers'

const finance = { id: 'g1', name: 'Finance', description: 'money', member_count: 2, roles: ['auditor'], created_at: '2026-09-16T00:00:00Z', updated_at: '2026-09-16T00:00:00Z' }
const roles = [
  { id: 'r-owner', slug: 'owner', display_name: 'Owner', builtin: true, permissions: [] },
  { id: 'r-auditor', slug: 'auditor', display_name: 'Auditor', builtin: false, permissions: ['audit:read'] },
]

describe('groups console', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    useSession().apply({ user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: ['owner'] })
  })

  it('lists groups, validates the create dialog and confirms deletion with the member count', async () => {
    await router.push('/admin/groups')
    await router.isReady()
    const fetch = stubFetch((url, init) => {
      if (url.startsWith('/api/v1/admin/groups') && init?.method === 'POST' && url.endsWith('/remove')) return { status: 204, body: null }
      if (url === '/api/v1/admin/groups' && init?.method === 'POST') return { status: 201, body: { ...finance, id: 'g2', name: 'Ops', member_count: 0, roles: [] } }
      return { status: 200, body: { items: [finance] } }
    })
    const w = mountView(Groups)
    await flushPromises()
    expect(w.findAll('[data-test="group-row"]').length).toBe(1)
    expect(w.find('[data-test="member-count"]').text()).toBe('2')
    // Create: an empty name never posts.
    await w.find('[data-test="new-group"]').trigger('click')
    await flushPromises()
    expect(q('[data-test="group-dialog"]')).not.toBeNull()
    const save = () => [...document.querySelectorAll('[data-test="group-dialog"] button')].find((b) => b.textContent?.trim() === 'Save') as HTMLButtonElement
    save().click()
    await flushPromises()
    expect(fetch).not.toHaveBeenCalledWith('/api/v1/admin/groups', expect.objectContaining({ method: 'POST' }))
    expect(q('[data-test="group-dialog"] [role=alert]').textContent).toBeTruthy()
    await type('[data-test="group-dialog"] input[data-field="name"]', ' Ops ')
    save().click()
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/groups', expect.objectContaining({ method: 'POST', body: JSON.stringify({ name: 'Ops', description: '' }) }))
    expect(w.findAll('[data-test="group-row"]').length).toBe(2)
    // Delete: the confirmation shows the member count and posts it back.
    await w.find('[data-test="delete-group"]').trigger('click')
    await flushPromises()
    expect(q('[data-test="delete-dialog"] [data-test="delete-summary"]').textContent).toContain('2 members')
    await click('[data-test="delete-dialog"] [data-test="confirm-delete"]')
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/groups/g1/remove', expect.objectContaining({ method: 'POST', body: JSON.stringify({ member_count: 2 }) }))
    w.unmount()
  })

  it('shows members and roles of a group, adds and removes a member, saves roles', async () => {
    await router.push('/admin/groups/g1')
    await router.isReady()
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/admin/groups/g1') return { status: 200, body: finance }
      if (url === '/api/v1/admin/groups/g1/members' && init?.method === 'POST') return { status: 200, body: { added: 1 } }
      if (url === '/api/v1/admin/groups/g1/members') return { status: 200, body: { items: [{ user_id: 'u2', email: 'bob@x.test', display_name: 'Bob', status: 'active', avatar_url: '', added_at: '2026-09-16T00:00:00Z' }] } }
      if (url.endsWith('/remove')) return { status: 204, body: null }
      if (url === '/api/v1/admin/groups/g1/roles') return { status: 200, body: { roles: ['auditor'] } }
      if (url.startsWith('/api/v1/admin/users')) return { status: 200, body: { items: [{ id: 'u3', email: 'dana@x.test', display_name: 'Dana', status: 'active', roles: [], groups: [] }] } }
      return { status: 200, body: roles }
    })
    const w = mountView(GroupDetail)
    await flushPromises()
    expect(w.find('[data-test="group-name"]').text()).toBe('Finance')
    expect(w.findAll('[data-test="member-row"]').length).toBe(1)
    // The owner role is never offered for a group.
    expect(w.findAll('[data-test="group-role"]').length).toBe(1)
    await w.find('[data-test="save-roles"]').trigger('click')
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/groups/g1/roles', expect.objectContaining({ method: 'PUT', body: JSON.stringify({ role_ids: ['r-auditor'] }) }))
    await w.find('[data-test="remove-member"]').trigger('click')
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/groups/g1/members/u2/remove', expect.objectContaining({ method: 'POST' }))
    expect(w.findAll('[data-test="member-row"]').length).toBe(0)
    w.unmount()
  })

  it('shows effective roles with their sources and group membership on the user page', async () => {
    await router.push('/admin/users/u3')
    await router.isReady()
    stubFetch((url) => {
      if (url.endsWith('/effective-roles')) return { status: 200, body: { items: [{ role_id: 'r-auditor', slug: 'auditor', sources: [{ kind: 'direct' }, { kind: 'group', group_id: 'g1', group_name: 'Finance' }] }] } }
      if (url.endsWith('/groups')) return { status: 200, body: { items: [{ id: 'g1', name: 'Finance' }] } }
      if (url.startsWith('/api/v1/admin/users')) return { status: 200, body: { items: [{ id: 'u3', email: 'dana@x.test', display_name: 'Dana', status: 'active', mfa_enabled: false, roles: ['auditor'], last_signin_at: null, groups: [{ id: 'g1', name: 'Finance' }] }] } }
      return { status: 200, body: roles }
    })
    const w = mountView(UserDetail)
    await flushPromises()
    const chips = w.findAll('[data-test="effective-role"]')
    expect(chips.length).toBe(1)
    expect(chips[0]!.text()).toContain('auditor')
    expect(chips[0]!.text()).toContain('direct, via Finance')
    expect(w.findAll('[data-test="user-group"]').length).toBe(1)
    w.unmount()
  })
})
