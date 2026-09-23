import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Roles from '@/views/admin/Roles.vue'
import RoleEditor from '@/views/admin/RoleEditor.vue'
import { router } from '@/router'
import { useSession } from '@/stores/session'
import { body, mountView, stubFetch } from './helpers'

const roles = [
  { id: 'r-owner', slug: 'owner', display_name: 'Owner', builtin: true, permissions: [] },
  { id: 'r-auditor', slug: 'auditor', display_name: 'Auditor', builtin: false, permissions: ['audit:read'] },
]
const perms = [
  { resource: 'audit', action: 'read', description: 'Read the trail' },
  { resource: 'invoices', action: 'read', description: '' },
  { resource: 'invoices', action: 'write', description: '' },
]

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
    expect(rows[0]!.find('[data-test="builtin"]').exists()).toBe(true)
    expect(rows[0]!.find('[data-test="remove"]').exists()).toBe(false)
    expect(rows[1]!.find('[data-test="remove"]').exists()).toBe(true)
    await rows[1]!.find('[data-test="remove"]').trigger('click')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/remove'))).toBe(false)
    ;([...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent?.trim() === 'Remove') as HTMLButtonElement).click()
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/roles/r-auditor/remove', expect.objectContaining({ method: 'POST' }))
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
    expect(b.permissions.sort()).toEqual(['invoices:read', 'invoices:write'])
    w.unmount()
  })

  it('shows the escalation refusal and locks built-ins in the editor', async () => {
    stubFetch((url, init) => {
      if (url.startsWith('/api/v1/admin/permissions')) return { status: 200, body: perms }
      if (init?.method === 'PUT') return { status: 403, body: { reason: 'self_escalation' } }
      return { status: 200, body: roles }
    })
    await router.push('/admin/roles/r-auditor')
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
})
