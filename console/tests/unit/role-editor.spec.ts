import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import RoleEditor from '@/views/admin/RoleEditor.vue'
import RoleGroupPickers from '@/views/admin/RoleGroupPickers.vue'
import { router } from '@/router'
import { useSession } from '@/stores/session'
import type { Role } from '@/composables/useRoles'
import { body, mountView, stubFetch } from './helpers'

const perm = (module: string, display: string, resource: string, action: string, grantable = true, description = '') => ({ ref: `${module}:${resource}:${action}`, module, module_display_name: display, resource, action, description, grantable, legacy: false })
const legacy = (resource: string, action: string) => ({ ref: `${resource}:${action}`, module: '', module_display_name: 'Before modules', resource, action, description: 'old grant', grantable: true, legacy: true })
// Deliberately out of order: the editor sorts by module display name, resource, action.
const catalogue = [
  perm('warden', 'Warden', 'secrets', 'read', true, 'Read secrets'),
  perm('warden', 'Warden', 'backup', 'manage', false, 'Export backups'),
  perm('auth', 'Authentication', 'users', 'read'),
  perm('auth', 'Authentication', 'audit', 'read'),
  perm('lcm', 'Certificates', 'backup', 'manage'),
  perm('warden', 'Warden', 'secrets', 'write', true),
  legacy('backup', 'manage'),
]
const roles = [
  { id: 'r-plain', slug: 'plain', display_name: 'Plain', builtin: false, origin: 'custom', locked: false, retired: false, permissions: ['warden:secrets:read'] },
  { id: 'r-old', slug: 'old', display_name: 'Old', builtin: false, origin: 'custom', locked: false, retired: false, permissions: ['backup:manage', 'warden:secrets:read'] },
]
const texts = (els: { text(): string }[]) => els.map((e) => e.text())

describe('role editor (module-scoped permissions)', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    useSession().apply({ user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: ['admin'] })
    await router.push('/admin/roles')
    await router.isReady()
  })

  function stub() {
    return stubFetch((url, init) => {
      if (url.startsWith('/api/v1/admin/permissions')) return { status: 200, body: catalogue }
      if (init?.method === 'POST' || init?.method === 'PUT') return { status: 200, body: { id: 'r-x' } }
      return { status: 200, body: roles }
    })
  }
  const submitted = (fetch: ReturnType<typeof stub>, method: string) => body(fetch.mock.calls.find((c) => (c[1] as RequestInit | undefined)?.method === method))

  it('groups by module display name, then resource, with action — description labels', async () => {
    stub()
    await router.push('/admin/roles/new')
    const w = mountView(RoleEditor)
    await flushPromises()
    const modules = w.findAll('[data-test="module"]')
    expect(modules.map((m) => m.find('h3').text())).toEqual(['Authentication', 'Certificates', 'Warden'])
    expect(texts(modules[2]!.findAll('[data-test="group"] h4'))).toEqual(['backup', 'secrets'])
    expect(texts(modules[0]!.findAll('[data-test="group"] h4'))).toEqual(['audit', 'users'])
    const warden = texts(modules[2]!.findAll('[data-test="perm"]'))
    expect(warden).toEqual(['manage — Export backups', 'read — Read secrets', 'write'])
    expect(w.find('[data-test="legacy"]').exists()).toBe(false)
    w.unmount()
  })

  it('selects the same action under two modules independently and submits qualified refs', async () => {
    const fetch = stub()
    await router.push('/admin/roles/new')
    const w = mountView(RoleEditor)
    await flushPromises()
    await w.find('[data-test="slug"] input').setValue('backups')
    await w.find('[data-test="name"] input').setValue('Backups')
    await w.find('[id="perm-lcm:backup:manage"]').setValue(true)
    expect((w.find('[id="perm-warden:backup:manage"]').element as HTMLInputElement).checked).toBe(false)
    await w.find('[data-test="save"]').trigger('click')
    await flushPromises()
    expect(submitted(fetch, 'POST')).toEqual({ slug: 'backups', display_name: 'Backups', permissions: ['lcm:backup:manage'] })
    w.unmount()
  })

  it('"Select all" and "Clear" in a module only toggle grantable permissions; non-grantable ones are disabled', async () => {
    const fetch = stub()
    await router.push('/admin/roles/new')
    const w = mountView(RoleEditor)
    await flushPromises()
    const warden = () => w.findAll('[data-test="module"]')[2]!
    const denied = warden().find('[id="perm-warden:backup:manage"]')
    expect((denied.element as HTMLInputElement).disabled).toBe(true)
    expect(warden().find('[title="You do not hold this permission"]').exists()).toBe(true)
    await warden().find('[data-test="select-all"]').trigger('click')
    await w.find('[data-test="slug"] input').setValue('ops')
    await w.find('[data-test="name"] input').setValue('Ops')
    await w.find('[data-test="save"]').trigger('click')
    await flushPromises()
    expect(submitted(fetch, 'POST').permissions.sort()).toEqual(['warden:secrets:read', 'warden:secrets:write'])
    // Other modules are untouched.
    expect((w.find('[id="perm-auth:audit:read"]').element as HTMLInputElement).checked).toBe(false)
    await w.find('[id="perm-auth:audit:read"]').setValue(true)
    await warden().find('[data-test="clear"]').trigger('click')
    expect((w.find('[id="perm-warden:secrets:read"]').element as HTMLInputElement).checked).toBe(false)
    expect((w.find('[id="perm-auth:audit:read"]').element as HTMLInputElement).checked).toBe(true)
    w.unmount()
  })

  it('"Before modules" appears only when the role holds legacy grants, read-only, and is kept on save', async () => {
    const fetch = stub()
    await router.push('/admin/roles/r-plain')
    const plain = mountView(RoleEditor)
    await flushPromises()
    expect(plain.find('[data-test="legacy"]').exists()).toBe(false)
    plain.unmount()
    await router.push('/admin/roles/r-old')
    const w = mountView(RoleEditor)
    await flushPromises()
    const section = w.find('[data-test="legacy"]')
    expect(section.exists()).toBe(true)
    expect(section.text()).toContain('Before modules')
    const box = section.find('input').element as HTMLInputElement
    expect(box.checked).toBe(true)
    expect(box.disabled).toBe(true)
    await w.find('[id="perm-warden:secrets:write"]').setValue(true)
    await w.find('[data-test="save"]').trigger('click')
    await flushPromises()
    expect(submitted(fetch, 'PUT').permissions.sort()).toEqual(['backup:manage', 'warden:secrets:read', 'warden:secrets:write'])
    w.unmount()
  })
})

describe('role pickers', () => {
  const pickerRoles: Role[] = [
    { id: 'r1', slug: 'member', display_name: 'Member', builtin: true, origin: 'builtin', retired: false },
    { id: 'r2', slug: 'm.warden.viewer', display_name: 'Warden viewer', origin: 'module', module_display_name: 'Warden', retired: false },
    { id: 'r3', slug: 'm.legacy.reader', display_name: 'Legacy reader', origin: 'module', module_display_name: 'Legacy', retired: true },
  ]
  it('labels module roles with their module and does not offer retired roles unless already held', async () => {
    const w = mount(RoleGroupPickers, { props: { prefix: 'p', roles: pickerRoles, groups: [], roleIds: [], groupIds: [] } })
    const labels = w.findAll('[data-test="p-roles"] label').map((l) => l.text())
    expect(labels).toContain('Warden viewer · Warden')
    expect(labels).toContain('Member')
    expect((w.find('#p-role-r3').element as HTMLInputElement).disabled).toBe(true)
    expect((w.find('#p-role-r2').element as HTMLInputElement).disabled).toBe(false)
    await w.setProps({ roleIds: ['r3'] })
    expect((w.find('#p-role-r3').element as HTMLInputElement).disabled).toBe(false)
  })
})
