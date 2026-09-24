import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Users from '@/views/admin/Users.vue'
import UserDetail from '@/views/admin/UserDetail.vue'
import InviteDialog from '@/views/admin/InviteDialog.vue'
import Audit from '@/views/admin/Audit.vue'
import Policy from '@/views/admin/Policy.vue'
import { router } from '@/router'
import { useSession } from '@/stores/session'
import { body, click, mountView, q, stubFetch, type } from './helpers'

const users = [
  { id: 'u1', email: 'alice@x.test', display_name: 'Alice', status: 'active', mfa_enabled: true, roles: ['owner'], last_signin_at: null },
  { id: 'u2', email: 'bob@x.test', display_name: 'Bob', status: 'deactivated', mfa_enabled: false, roles: [], last_signin_at: null },
]
const roles = [
  { id: 'r-admin', slug: 'admin', display_name: 'Admin', builtin: true, permissions: [] },
  { id: 'r-auditor', slug: 'auditor', display_name: 'Auditor', builtin: false, permissions: ['audit:read'] },
]

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
    const w = mountView(Users)
    await flushPromises()
    expect(w.findAll('[data-test="user-row"]').length).toBe(2)
    expect(w.find('[data-test="deactivate"]').exists()).toBe(true)
    expect(w.find('[data-test="reactivate"]').exists()).toBe(true)
    await w.find('[data-test="reactivate"]').trigger('click')
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/users/u2/reactivate', expect.objectContaining({ method: 'POST' }))
    expect(w.find('[role=status]').text()).toContain('bob@x.test')
    await w.find('[data-test="search"] input').setValue('bob')
    await new Promise((r) => setTimeout(r, 300))
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).includes('/api/v1/admin/users?q=bob'))).toBe(true)
    w.unmount()
  })

  it('lists imported users with an imported chip and a directory-origin tooltip', async () => {
    const imported = {
      id: 'u3',
      email: 'cy@corp.test',
      display_name: 'Cy By',
      status: 'imported',
      mfa_enabled: false,
      roles: [],
      last_signin_at: null,
      invitation_id: null,
      directory: { connection_id: 'd1', connection_name: 'Corp AD', directory_uid: 'abc-123', last_imported_at: '2026-09-23T08:00:00Z' },
    }
    stubFetch((url) => {
      if (url.startsWith('/api/v1/admin/users')) return { status: 200, body: { items: [users[0], imported] } }
      if (url.startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Users)
    await flushPromises()
    expect(w.findAll('[data-test="user-row"]').length).toBe(2)
    expect(w.findAll('[data-test="status-chip"]').map((c) => c.text())).toEqual(['active', 'imported'])
    const origins = w.findAll('[data-test="origin"]')
    expect(origins.length).toBe(1)
    expect(origins[0]!.attributes('title')).toBe('Imported from Corp AD at 2026-09-23T08:00:00Z')
    w.unmount()
  })

  it('offers imported in the status filter and reloads with status=imported', async () => {
    const fetch = stubFetch((url) => {
      if (url.startsWith('/api/v1/admin/users')) return { status: 200, body: { items: users } }
      if (url.startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Users)
    await flushPromises()
    const sel = w.find('[data-test="status"] select').element as HTMLSelectElement
    expect([...sel.options].map((o) => o.value)).toEqual(['', 'invited', 'active', 'deactivated', 'imported'])
    sel.value = 'imported'
    sel.dispatchEvent(new Event('change'))
    await new Promise((r) => setTimeout(r, 300))
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).includes('/api/v1/admin/users?') && String(c[0]).includes('status=imported'))).toBe(true)
    w.unmount()
  })

  it('confirms deactivation and maps refusal reasons to messages', async () => {
    const fetch = stubFetch((url) => {
      if (url.startsWith('/api/v1/admin/users') && !url.includes('/deactivate')) return { status: 200, body: { items: users } }
      if (url.startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      return { status: 403, body: { reason: 'last_owner' } }
    })
    const w = mountView(Users)
    await flushPromises()
    await w.find('[data-test="deactivate"]').trigger('click')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/deactivate'))).toBe(false)
    const buttons = [...document.querySelectorAll('[role=dialog] button')] as HTMLButtonElement[]
    buttons.find((b) => b.textContent?.trim() === 'Deactivate')!.click()
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/users/u1/deactivate', expect.objectContaining({ method: 'POST' }))
    expect(w.find('[data-test="error"]').text()).toMatch(/last owner/i)
    w.unmount()
  })

  it('validates the invite dialog with zod and posts email + roles', async () => {
    const fetch = stubFetch(() => ({ status: 202, body: { queued: true } }))
    const w = mountView(InviteDialog, { modelValue: true, roles })
    await flushPromises()
    const posted = () => fetch.mock.calls.filter((c) => String(c[0]) === '/api/v1/admin/invitations')
    await click('[data-test="invite-send"]')
    expect(posted().length).toBe(0)
    expect(q('[data-test="invite-email"] [role=alert]').textContent).toBeTruthy()
    await type('[data-test="invite-email"] input', 'not-an-email')
    await click('[data-test="invite-send"]')
    expect(posted().length).toBe(0)
    await type('[data-test="invite-email"] input', 'new@x.test')
    await click('[data-test="invite-send"]')
    expect(body(posted()[0])).toEqual({ email: 'new@x.test', role_ids: [] })
    expect(w.findComponent(InviteDialog).emitted('sent')).toBeTruthy()
    w.unmount()
  })

  it('invite dialog sends groups and names when given (feature 004)', async () => {
    const fetch = stubFetch((url) => (url.startsWith('/api/v1/admin/groups') ? { status: 200, body: { items: [{ id: 'g1', name: 'Finance', member_count: 1, roles: ['auditor'] }] } } : { status: 202, body: { queued: true } }))
    const w = mountView(InviteDialog, { modelValue: true, roles })
    await flushPromises()
    await type('[data-test="invite-email"] input', 'new@x.test')
    await type('[data-test="invite-first-name"] input', 'Dana')
    await type('[data-test="invite-last-name"] input', ' Kovač ')
    const group = q<HTMLInputElement>('[data-test="invite-groups"] input[type=checkbox]')
    group.checked = true
    group.dispatchEvent(new Event('change'))
    await flushPromises()
    await click('[data-test="invite-send"]')
    const call = fetch.mock.calls.find((c) => String(c[0]) === '/api/v1/admin/invitations')
    expect(body(call)).toEqual({ email: 'new@x.test', role_ids: [], group_ids: ['g1'], first_name: 'Dana', last_name: 'Kovač' })
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
    const w = mountView(UserDetail)
    await flushPromises()
    const boxes = w.findAll('[data-test="role"] input')
    expect(boxes.length).toBe(2)
    await boxes[0]!.setValue(true)
    await boxes[1]!.setValue(true)
    await w.find('[data-test="save"]').trigger('click')
    await flushPromises()
    const call = fetch.mock.calls.find((c) => String(c[0]) === '/api/v1/admin/users/u2/roles')
    expect(body(call).role_ids.sort()).toEqual(['r-admin', 'r-auditor'])
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
    const w = mountView(UserDetail)
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
    const list = mountView(Users)
    await flushPromises()
    expect(list.findAll('[data-test="user-avatar"]').length).toBe(users.length)
    expect(list.find('[data-test="user-avatar"] img').exists()).toBe(true)
    list.unmount()
  })

  it('builds audit queries from the filters and pages with the cursor', async () => {
    const fetch = stubFetch((url) => {
      if (url.includes('cursor=')) return { status: 200, body: { items: [{ ts: '2026-09-22T10:00:00Z', event_type: 'signin_ok', outcome: 'ok', actor_kind: 'user', details: {} }] } }
      return { status: 200, body: { items: [{ ts: '2026-09-22T09:00:00Z', event_type: 'signin_failed', outcome: 'refused', actor_kind: 'user', reason: 'wrong_password', details: {} }], next_cursor: 'c1' } }
    })
    await router.push('/admin/audit')
    const w = mountView(Audit)
    await flushPromises()
    expect(w.findAll('[data-test="audit-row"]').length).toBe(1)
    await w.find('[data-test="filter-user"] input').setValue('u2')
    await w.find('[data-test="apply"]').trigger('click')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).includes('user_id=u2'))).toBe(true)
    const more = w.findAll('button').find((b) => b.text() === 'Load more')!
    await more.trigger('click')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).includes('cursor=c1'))).toBe(true)
    expect(w.findAll('[data-test="audit-row"]').length).toBe(2)
    w.unmount()
  })

  it('validates the security policy with zod (durations, bounds, idle ≤ session) and saves it', async () => {
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/admin/policy' && init?.method === 'PUT') return { status: 200, body: JSON.parse(String(init.body)) }
      return { status: 200, body: { session_lifetime: '8h', idle_timeout: '1h', access_token_lifetime: '15m', password_min_length: 12, mfa_required: false, lockout_threshold: 10, lockout_duration: '15m' } }
    })
    await router.push('/admin/policy')
    const w = mountView(Policy)
    await flushPromises()
    expect((w.find('[data-test="session_lifetime"] input').element as HTMLInputElement).value).toBe('8h')
    await w.find('[data-test="idle_timeout"] input').setValue('9h')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => (c[1] as RequestInit)?.method === 'PUT')).toBe(false)
    expect(w.find('[data-test="idle_timeout"] [role=alert]').text()).toMatch(/session lifetime/)
    await w.find('[data-test="idle_timeout"] input').setValue('30m')
    await w.find('[data-test="lockout_threshold"] input').setValue('5')
    await w.find('form').trigger('submit')
    await flushPromises()
    const call = fetch.mock.calls.find((c) => (c[1] as RequestInit)?.method === 'PUT')
    expect(body(call)).toMatchObject({ idle_timeout: '30m', lockout_threshold: 5, mfa_required: false })
    expect(w.find('[data-test="saved"]').exists()).toBe(true)
    w.unmount()
  })
})
