import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import Users from '@/views/admin/Users.vue'
import UserDetail from '@/views/admin/UserDetail.vue'
import InviteDialog from '@/views/admin/InviteDialog.vue'
import Audit from '@/views/admin/Audit.vue'
import { router } from '@/router'
import { useSession } from '@/stores/session'

type Reply = { status: number; body: unknown }
function stubFetch(handler: (url: string, init?: RequestInit) => Reply) {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const { status, body } = handler(String(input), init)
    return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

const users = [
  { id: 'u1', email: 'alice@x.test', display_name: 'Alice', status: 'active', mfa_enabled: true, roles: ['owner'], last_signin_at: null },
  { id: 'u2', email: 'bob@x.test', display_name: 'Bob', status: 'deactivated', mfa_enabled: false, roles: [], last_signin_at: null },
]
const roles = [
  { id: 'r-admin', slug: 'admin', display_name: 'Admin', builtin: true, permissions: [] },
  { id: 'r-auditor', slug: 'auditor', display_name: 'Auditor', builtin: false, permissions: ['audit:read'] },
]

function plugins() {
  return [createVuetify({ components, directives }), router]
}

describe('admin console', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    const s = useSession()
    s.apply({ user: { id: 'u1', email: 'alice@x.test' }, tenant: { id: 't1', slug: 'acme' }, roles: ['owner'] })
    await router.push('/admin/users')
    await router.isReady()
  })

  it('lists users, filters by search/status and offers status actions', async () => {
    const fetch = stubFetch((url) => {
      if (url.startsWith('/api/v1/admin/users')) return { status: 200, body: { items: url.includes('status=deactivated') ? users.slice(1) : users } }
      if (url.startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      if (url.endsWith('/reactivate')) return { status: 204, body: null }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mount(Users, { global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    expect(w.findAll('[data-test="user-row"]').length).toBe(2)
    expect(w.find('[data-test="deactivate"]').exists()).toBe(true)
    expect(w.find('[data-test="reactivate"]').exists()).toBe(true)
    await w.find('[data-test="reactivate"]').trigger('click')
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/users/u2/reactivate', expect.objectContaining({ method: 'POST' }))
    expect(w.find('[data-test="notice"]').text()).toContain('bob@x.test')
    await w.find('[data-test="search"] input').setValue('bob')
    await new Promise((r) => setTimeout(r, 300))
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).includes('/api/v1/admin/users?q=bob'))).toBe(true)
    w.unmount()
  })

  it('maps refusal reasons to messages', async () => {
    stubFetch((url) => {
      if (url.startsWith('/api/v1/admin/users') && !url.includes('/deactivate')) return { status: 200, body: { items: users } }
      if (url.startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      return { status: 403, body: { reason: 'last_owner' } }
    })
    const w = mount(Users, { global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    await w.find('[data-test="deactivate"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="error"]').text()).toMatch(/last owner/i)
    w.unmount()
  })

  it('validates the invite dialog and posts email + roles', async () => {
    const fetch = stubFetch(() => ({ status: 202, body: { queued: true } }))
    const w = mount(InviteDialog, { props: { modelValue: true, roles }, global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    const send = () => document.querySelector('[data-test="invite-send"]') as HTMLButtonElement
    expect(send().disabled).toBe(true)
    const email = document.querySelector('[data-test="invite-email"] input') as HTMLInputElement
    email.value = 'not-an-email'
    email.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(send().disabled).toBe(true)
    email.value = 'new@x.test'
    email.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(send().disabled).toBe(false)
    send().click()
    await flushPromises()
    const call = fetch.mock.calls.find((c) => String(c[0]) === '/api/v1/admin/invitations')
    expect(JSON.parse(String((call?.[1] as RequestInit).body))).toEqual({ email: 'new@x.test', role_ids: [] })
    expect(w.emitted('sent')).toBeTruthy()
    w.unmount()
  })

  it('invite dialog sends groups and names when given (feature 004)', async () => {
    const fetch = stubFetch((url) => (url.startsWith('/api/v1/admin/groups') ? { status: 200, body: { items: [{ id: 'g1', name: 'Finance', member_count: 1, roles: ['auditor'] }] } } : { status: 202, body: { queued: true } }))
    const w = mount(InviteDialog, { props: { modelValue: true, roles }, global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    const type = (sel: string, v: string) => {
      const el = document.querySelector(sel) as HTMLInputElement
      el.value = v
      el.dispatchEvent(new Event('input'))
    }
    type('[data-test="invite-email"] input', 'new@x.test')
    type('[data-test="invite-first-name"] input', 'Dana')
    type('[data-test="invite-last-name"] input', ' Kovač ')
    await flushPromises()
    expect(document.querySelector('[data-test="invite-groups"]')).not.toBeNull()
    // Select the group through the select component (Vuetify menus are portal-rendered).
    const selects = w.findAllComponents({ name: 'VSelect' })
    const groupSelect = selects.find((c) => c.attributes('data-test') === 'invite-groups')!
    groupSelect.vm.$emit('update:modelValue', ['g1'])
    await flushPromises()
    ;(document.querySelector('[data-test="invite-send"]') as HTMLButtonElement).click()
    await flushPromises()
    const call = fetch.mock.calls.find((c) => String(c[0]) === '/api/v1/admin/invitations')
    expect(JSON.parse(String((call?.[1] as RequestInit).body))).toEqual({ email: 'new@x.test', role_ids: [], group_ids: ['g1'], first_name: 'Dana', last_name: 'Kovač' })
    w.unmount()
  })

  it('edits roles in the user detail and sends role ids', async () => {
    const fetch = stubFetch((url, init) => {
      if (url.startsWith('/api/v1/admin/users') && init?.method === 'GET') return { status: 200, body: { items: users } }
      if (url.startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      if (url.endsWith('/roles') && init?.method === 'PUT') return { status: 200, body: { roles: ['admin', 'auditor'] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    await router.push('/admin/users/u2')
    const w = mount(UserDetail, { global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    const boxes = w.findAll('[data-test="role"] input')
    expect(boxes.length).toBe(2)
    await boxes[0]!.setValue(true)
    await boxes[1]!.setValue(true)
    await w.find('[data-test="save"]').trigger('click')
    await flushPromises()
    const call = fetch.mock.calls.find((c) => String(c[0]) === '/api/v1/admin/users/u2/roles')
    expect(JSON.parse(String((call?.[1] as RequestInit).body)).role_ids.sort()).toEqual(['r-admin', 'r-auditor'])
    expect(w.find('[data-test="saved"]').exists()).toBe(true)
    w.unmount()
  })

  it('shows the profile panel on the user detail (admin: edit fields, remove avatar only) and avatars in the list', async () => {
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/admin/users/u2/profile' && init?.method === 'PUT') return { status: 200, body: { id: 'u2', email: 'bob@x.test', display_name: 'Robert K', first_name: 'Robert', last_name: 'K', phone: '+14155550100', avatar_url: '' } }
      if (url === '/api/v1/admin/users/u2/profile') return { status: 200, body: { id: 'u2', email: 'bob@x.test', display_name: 'Bob', first_name: '', last_name: '', phone: '', avatar_url: '/api/v1/users/u2/avatar/abc' } }
      if (url === '/api/v1/admin/users/u2/avatar' && init?.method === 'DELETE') return { status: 204, body: null }
      if (url.startsWith('/api/v1/admin/users') && init?.method === 'GET') return { status: 200, body: { items: users.map((u) => ({ ...u, avatar_url: u.id === 'u2' ? '/api/v1/users/u2/avatar/abc' : '' })) } }
      if (url.startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      return { status: 200, body: { items: [] } }
    })
    await router.push('/admin/users/u2')
    const w = mount(UserDetail, { global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    expect(w.find('[data-test="profile-form"]').exists()).toBe(true)
    expect(w.find('[data-test="avatar-upload"]').exists()).toBe(false) // admins remove, never upload for others
    await w.find('[data-test="avatar-remove"]').trigger('click')
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/users/u2/avatar', expect.objectContaining({ method: 'DELETE' }))
    await w.find('[data-test="first-name"] input').setValue('Robert')
    await w.find('[data-test="last-name"] input').setValue('K')
    await w.find('[data-test="phone"] input').setValue('+1 415 555 0100')
    await w.find('[data-test="profile-form"] form').trigger('submit')
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/users/u2/profile', expect.objectContaining({ method: 'PUT' }))
    expect(w.find('[data-test="profile-saved"]').exists()).toBe(true)
    w.unmount()
    // The list shows an avatar per row.
    await router.push('/admin/users')
    const list = mount(Users, { global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    expect(list.findAll('[data-test="user-avatar"]').length).toBe(users.length)
    expect(list.find('[data-test="user-row"]:nth-child(2) [data-test="user-avatar"] .v-img, [data-test="user-avatar"] img').exists()).toBe(true)
    list.unmount()
  })

  it('builds audit queries from the filters and pages with the cursor', async () => {
    const fetch = stubFetch((url) => {
      if (url.includes('cursor=')) return { status: 200, body: { items: [{ event_type: 'signin_ok', outcome: 'ok', actor_kind: 'user' }] } }
      return { status: 200, body: { items: [{ event_type: 'signin_failed', outcome: 'refused', actor_kind: 'user', reason: 'wrong_password' }], next_cursor: 'c1' } }
    })
    await router.push('/admin/audit')
    const w = mount(Audit, { global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    expect(w.findAll('[data-test="audit-row"]').length).toBe(1)
    await w.find('[data-test="filter-user"] input').setValue('u2')
    await w.find('[data-test="apply"]').trigger('click')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).includes('user_id=u2'))).toBe(true)
    await w.find('[data-test="more"]').trigger('click')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).includes('cursor=c1'))).toBe(true)
    expect(w.findAll('[data-test="audit-row"]').length).toBe(2)
    w.unmount()
  })
})
