import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Roles from '@/views/admin/Roles.vue'
import RoleEditor from '@/views/admin/RoleEditor.vue'
import UserDetail from '@/views/admin/UserDetail.vue'
import { router } from '@/router'
import { useSession } from '@/stores/session'
import { reasonMessage } from '@/api/vocab'
import { body, mountView, q, stubFetch, type } from './helpers'

const roles = [
  { id: 'r-owner', slug: 'owner', display_name: 'Owner', builtin: true, origin: 'builtin', locked: true, retired: false, permissions: [] },
  { id: 'r-billing', slug: 'billing', display_name: 'Billing', builtin: false, origin: 'custom', locked: false, retired: false, permissions: ['auth:audit:read'] },
]
const perm = (module: string, display: string, resource: string, action: string, description = '', grantable = true) => ({ ref: `${module}:${resource}:${action}`, module, module_display_name: display, resource, action, description, grantable, legacy: false })
const perms = [perm('auth', 'Authentication', 'audit', 'read', 'Read the trail'), perm('billing', 'Billing', 'invoices', 'read'), perm('billing', 'Billing', 'invoices', 'write')]
const moduleRoles = [
  ...roles,
  { id: 'r-admin', slug: 'admin', display_name: 'Administrator', builtin: true, origin: 'builtin', locked: true, retired: false, permissions: [] },
  { id: 'r-wv', slug: 'm.warden.viewer', display_name: 'Warden viewer', builtin: false, origin: 'module', module: 'warden', module_display_name: 'Warden', module_slug: 'viewer', locked: true, retired: false, retired_at: null, permissions: ['warden:secrets:read'] },
  { id: 'r-old', slug: 'm.legacy.reader', display_name: 'Legacy reader', builtin: false, origin: 'module', module: 'legacy', module_display_name: 'Legacy', module_slug: 'reader', locked: true, retired: true, retired_at: '2026-09-20T00:00:00Z', permissions: [] },
]
const dialogButton = (label: string) => [...document.querySelectorAll('[data-test="clone-dialog"] button')].find((b) => b.textContent?.trim() === label) as HTMLButtonElement

describe('roles console', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    useSession().apply({ user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: ['owner'] })
    await router.push('/admin/roles')
    await router.isReady()
  })

  it('locks built-in roles and confirms before removing custom ones', async () => {
    const fetch = stubFetch((url) => (url.startsWith('/api/v1/admin/roles') && !url.includes('/remove') ? { status: 200, body: roles } : { status: 204, body: null }))
    const w = mountView(Roles)
    await flushPromises()
    const rows = w.findAll('[data-test="role-row"]')
    expect(rows.length).toBe(2)
    expect(rows[0]!.find('[data-test="origin"]').text()).toBe('built-in')
    expect(rows[0]!.find('[data-test="remove"]').exists()).toBe(false)
    expect(rows[1]!.find('[data-test="remove"]').exists()).toBe(true)
    await rows[1]!.find('[data-test="remove"]').trigger('click')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/remove'))).toBe(false)
    ;([...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent?.trim() === 'Remove') as HTMLButtonElement).click()
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/roles/r-billing/remove', expect.objectContaining({ method: 'POST' }))
    w.unmount()
  })

  it('renders the permission matrix grouped by resource, validates the slug and posts the selection', async () => {
    const fetch = stubFetch((url, init) => {
      if (url.startsWith('/api/v1/admin/permissions')) return { status: 200, body: perms }
      if (url === '/api/v1/admin/roles' && init?.method === 'POST') return { status: 201, body: { id: 'r-new' } }
      return { status: 200, body: roles }
    })
    await router.push('/admin/roles/new')
    const w = mountView(RoleEditor)
    await flushPromises()
    expect(w.findAll('[data-test="module"]').length).toBe(2)
    expect(w.findAll('[data-test="group"]').length).toBe(2)
    expect(w.findAll('[data-test="perm"]').length).toBe(3)
    const posted = () => fetch.mock.calls.filter((c) => String(c[0]) === '/api/v1/admin/roles' && (c[1] as RequestInit).method === 'POST')
    await w.find('[data-test="save"]').trigger('click')
    await flushPromises()
    expect(posted().length).toBe(0)
    await w.find('[data-test="slug"] input').setValue('Owner')
    await w.find('[data-test="name"] input').setValue('Billing')
    await w.find('[data-test="save"]').trigger('click')
    await flushPromises()
    expect(posted().length).toBe(0) // reserved/invalid slug
    expect(w.find('[data-test="slug"] [role=alert]').exists()).toBe(true)
    await w.find('[data-test="slug"] input').setValue('billing')
    const boxes = w.findAll('[data-test="perm"] input')
    await boxes[1]!.setValue(true)
    await boxes[2]!.setValue(true)
    await w.find('[data-test="save"]').trigger('click')
    await flushPromises()
    const b = body(posted()[0])
    expect(b.slug).toBe('billing')
    expect(b.permissions.sort()).toEqual(['billing:invoices:read', 'billing:invoices:write'])
    w.unmount()
  })

  it('shows the escalation refusal and locks built-ins in the editor', async () => {
    stubFetch((url, init) => {
      if (url.startsWith('/api/v1/admin/permissions')) return { status: 200, body: perms }
      if (init?.method === 'PUT') return { status: 403, body: { reason: 'self_escalation' } }
      return { status: 200, body: roles }
    })
    await router.push('/admin/roles/r-billing')
    const w = mountView(RoleEditor)
    await flushPromises()
    expect(w.find('[data-test="name"] input').element.getAttribute('disabled')).toBeNull()
    await w.find('[data-test="save"]').trigger('click')
    await flushPromises()
    expect(w.text()).toMatch(/permissions you hold/i)
    w.unmount()
    await router.push('/admin/roles/r-owner')
    const b = mountView(RoleEditor)
    await flushPromises()
    expect(b.find('[data-test="builtin-lock"]').exists()).toBe(true)
    expect((b.find('[data-test="save"]').element as HTMLButtonElement).disabled).toBe(true)
    b.unmount()
  })
  it('shows origin and retired badges and offers edit/remove only on custom roles, clone on all but owner', async () => {
    stubFetch(() => ({ status: 200, body: moduleRoles }))
    const w = mountView(Roles)
    await flushPromises()
    const rows = w.findAll('[data-test="role-row"]')
    const row = (name: string) => rows.find((r) => r.text().includes(name))!
    expect(rows.length).toBe(5)
    expect(row('Owner').find('[data-test="origin"]').text()).toBe('built-in')
    expect(row('Billing').find('[data-test="origin"]').text()).toBe('custom')
    expect(row('Warden viewer').find('[data-test="origin"]').text()).toBe('Warden')
    expect(row('Warden viewer').find('[data-test="retired"]').exists()).toBe(false)
    const retired = row('Legacy reader').find('[data-test="retired"]')
    expect(retired.exists()).toBe(true)
    expect(row('Legacy reader').html()).toContain('No longer provided by Legacy; kept for existing assignments')
    for (const name of ['Owner', 'Administrator', 'Warden viewer', 'Legacy reader']) {
      expect(row(name).find('[data-test="edit"]').exists()).toBe(false)
      expect(row(name).find('[data-test="remove"]').exists()).toBe(false)
      expect(row(name).find('[data-test="view"]').exists()).toBe(true)
    }
    expect(row('Billing').find('[data-test="edit"]').exists()).toBe(true)
    expect(row('Billing').find('[data-test="remove"]').exists()).toBe(true)
    expect(row('Owner').find('[data-test="clone"]').exists()).toBe(false)
    for (const name of ['Administrator', 'Billing', 'Warden viewer', 'Legacy reader']) expect(row(name).find('[data-test="clone"]').exists()).toBe(true)
    w.unmount()
  })

  it('clones a role: suggests the slug from the name, shows refusals and opens the new role', async () => {
    let reply: { status: number; body: unknown } = { status: 409, body: { reason: 'conflict' } }
    const fetch = stubFetch((url) => {
      if (url.endsWith('/clone')) return reply
      if (url.startsWith('/api/v1/admin/permissions')) return { status: 200, body: perms }
      return { status: 200, body: moduleRoles }
    })
    const w = mountView(Roles)
    await flushPromises()
    const row = w.findAll('[data-test="role-row"]').find((r) => r.text().includes('Warden viewer'))!
    await row.find('[data-test="clone"]').trigger('click')
    await flushPromises()
    expect(q('[data-test="clone-dialog"]')).not.toBeNull()
    expect(q<HTMLInputElement>('[data-test="clone-slug"] input').value).toBe('warden-viewer-copy')
    await type('[data-test="clone-name"] input', '  Ops: Warden (Read) ')
    expect(q<HTMLInputElement>('[data-test="clone-slug"] input').value).toBe('ops-warden-read')
    await type('[data-test="clone-name"] input', 'X'.repeat(80))
    expect(q<HTMLInputElement>('[data-test="clone-slug"] input').value).toBe('x'.repeat(63))
    await type('[data-test="clone-name"] input', 'Warden readers')
    expect(q<HTMLInputElement>('[data-test="clone-slug"] input').value).toBe('warden-readers')
    // A manually edited slug is no longer overwritten by the suggestion.
    await type('[data-test="clone-slug"] input', 'readers')
    await type('[data-test="clone-name"] input', 'Warden readers team')
    expect(q<HTMLInputElement>('[data-test="clone-slug"] input').value).toBe('readers')
    const clones = () => fetch.mock.calls.filter((c) => String(c[0]).endsWith('/clone'))
    // Invalid slugs never reach the server.
    await type('[data-test="clone-slug"] input', 'm.warden.x')
    dialogButton('Clone').click()
    await flushPromises()
    expect(clones().length).toBe(0)
    await type('[data-test="clone-slug"] input', 'readers')
    dialogButton('Clone').click()
    await flushPromises()
    expect(clones().length).toBe(1)
    expect(clones()[0]![0]).toBe('/api/v1/admin/roles/r-wv/clone')
    expect(body(clones()[0])).toEqual({ slug: 'readers', display_name: 'Warden readers team' })
    expect(q('[data-test="clone-error"]').textContent).toMatch(/already exists/i)
    reply = { status: 403, body: { reason: 'self_escalation' } }
    dialogButton('Clone').click()
    await flushPromises()
    expect(q('[data-test="clone-error"]').textContent).toMatch(/permissions you hold/i)
    reply = { status: 201, body: { id: 'r-new', slug: 'readers', display_name: 'Warden readers team', origin: 'custom', permissions: ['warden:secrets:read'] } }
    dialogButton('Clone').click()
    await flushPromises()
    expect(router.currentRoute.value.name).toBe('admin-role')
    expect(router.currentRoute.value.params.id).toBe('r-new')
    w.unmount()
  })

  it('opens module roles read-only with an origin banner and a Clone action', async () => {
    stubFetch((url) => {
      if (url.startsWith('/api/v1/admin/permissions')) return { status: 200, body: [...perms, perm('warden', 'Warden', 'secrets', 'read', 'Read secrets')] }
      return { status: 200, body: moduleRoles }
    })
    await router.push('/admin/roles/r-wv')
    const w = mountView(RoleEditor)
    await flushPromises()
    expect(w.find('[data-test="module-lock"]').text()).toContain('Warden')
    expect((w.find('[data-test="save"]').element as HTMLButtonElement).disabled).toBe(true)
    expect(w.find('[data-test="name"] input').element.getAttribute('disabled')).not.toBeNull()
    expect(w.findAll('[data-test="perm"] input').every((i) => (i.element as HTMLInputElement).disabled)).toBe(true)
    expect(w.find('[data-test="clone"]').exists()).toBe(true)
    await w.find('[data-test="clone"]').trigger('click')
    await flushPromises()
    expect(q('[data-test="clone-dialog"]')).not.toBeNull()
    w.unmount()
    await router.push('/admin/roles/r-owner')
    const o = mountView(RoleEditor)
    await flushPromises()
    expect(o.find('[data-test="builtin-lock"]').exists()).toBe(true)
    expect(o.find('[data-test="clone"]').exists()).toBe(false)
    o.unmount()
    await router.push('/admin/roles/r-admin')
    const a = mountView(RoleEditor)
    await flushPromises()
    expect(a.find('[data-test="builtin-lock"]').exists()).toBe(true)
    expect(a.find('[data-test="clone"]').exists()).toBe(true)
    a.unmount()
  })

  it('keeps a held retired role on the user page, never offers other retired roles and shows role_retired', async () => {
    const extra = { ...moduleRoles[4]!, id: 'r-old2', slug: 'm.legacy.writer', display_name: 'Legacy writer' }
    const fetch = stubFetch((url, init) => {
      if (url.startsWith('/api/v1/admin/users') && url.endsWith('/roles') && init?.method === 'PUT') return { status: 409, body: { reason: 'role_retired' } }
      if (url.startsWith('/api/v1/admin/users') && !url.includes('/u2/')) return { status: 200, body: { items: [{ id: 'u2', email: 'bob@x.test', display_name: 'Bob', status: 'active', mfa_enabled: false, roles: ['m.legacy.reader'], last_signin_at: null }] } }
      if (url.startsWith('/api/v1/admin/roles')) return { status: 200, body: [...moduleRoles, extra] }
      return { status: 404, body: { reason: 'not_found' } }
    })
    await router.push('/admin/users/u2')
    const w = mountView(UserDetail)
    await flushPromises()
    const box = (rid: string) => w.find(`[id="role-${rid}"]`).element as HTMLInputElement
    expect(box('r-old').checked).toBe(true)
    expect(box('r-old').disabled).toBe(false)
    expect(box('r-old2').disabled).toBe(true)
    expect(box('r-wv').disabled).toBe(false)
    expect(w.findAll('[data-test="role"]').map((r) => r.text()).some((t) => t.startsWith('Warden viewer · Warden'))).toBe(true)
    await w.find('[data-test="save"]').trigger('click')
    await flushPromises()
    expect(body(fetch.mock.calls.find((c) => String(c[0]) === '/api/v1/admin/users/u2/roles')).role_ids).toEqual(['r-old'])
    expect(w.text()).toMatch(/no longer provided by its module/i)
    w.unmount()
  })

  it('shows the managed-role refusal wording', () => {
    expect(reasonMessage('managed_role')).toMatch(/clone it to customise/i)
    expect(reasonMessage('role_retired')).toMatch(/no longer provided by its module/i)
  })
})
