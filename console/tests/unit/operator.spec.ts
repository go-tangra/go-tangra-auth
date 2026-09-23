import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Tenants from '@/views/operator/Tenants.vue'
import TenantDetail from '@/views/operator/TenantDetail.vue'
import Clients from '@/views/admin/Clients.vue'
import { router } from '@/router'
import { useSession } from '@/stores/session'
import { body, click, mountView, q, stubFetch, type } from './helpers'

const tenants = [
  { id: 't-platform', slug: 'platform', display_name: 'Platform', status: 'active', kind: 'platform', created_at: '2026-01-01T00:00:00Z' },
  { id: 't-acme', slug: 'acme', display_name: 'Acme', status: 'active', kind: 'customer', created_at: '2026-01-02T00:00:00Z' },
]
const dialogButton = (label: string) => [...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent?.trim() === label) as HTMLButtonElement

describe('operator console', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    useSession().apply({ user: { id: 'op', email: 'ops@x.test' }, tenant: { id: 't-platform' }, roles: ['owner'], operator: true })
    await router.push('/operator/tenants')
    await router.isReady()
  })

  it('lists tenants and validates the create form before posting', async () => {
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/operator/tenants' && init?.method === 'POST') return { status: 201, body: { tenant: { id: 't-new' }, invitation_id: 'i1' } }
      return { status: 200, body: { items: tenants } }
    })
    const w = mountView(Tenants)
    await flushPromises()
    expect(w.findAll('[data-test="tenant-row"]').length).toBe(2)
    await w.find('[data-test="create-open"]').trigger('click')
    await flushPromises()
    const posted = () => fetch.mock.calls.filter((c) => String(c[0]) === '/api/v1/operator/tenants' && (c[1] as RequestInit).method === 'POST')
    dialogButton('Create').click()
    await flushPromises()
    expect(posted().length).toBe(0)
    await type('[data-test="create-dialog"] input[data-field="slug"]', 'Globex Inc')
    await type('[data-test="create-dialog"] input[data-field="display_name"]', 'Globex')
    await type('[data-test="create-dialog"] input[data-field="owner_email"]', 'owner@globex.test')
    dialogButton('Create').click()
    await flushPromises()
    expect(posted().length).toBe(0)
    expect(q('[data-test="create-dialog"] [role=alert]').textContent).toMatch(/lowercase/)
    await type('[data-test="create-dialog"] input[data-field="slug"]', 'globex')
    dialogButton('Create').click()
    await flushPromises()
    expect(body(posted()[0])).toEqual({ slug: 'globex', display_name: 'Globex', owner_email: 'owner@globex.test' })
    expect(w.find('[data-test="notice"]').text()).toContain('globex')
    w.unmount()
  })

  it('asks for confirmation before suspending and creates audited grants', async () => {
    const fetch = stubFetch((url, init) => {
      if (url.endsWith('/suspend')) return { status: 204, body: null }
      if (url.endsWith('/operator/grants')) return { status: 201, body: { id: 'g1', expires_at: '2026-09-16T13:00:00Z' } }
      if (init?.method === 'GET') return { status: 200, body: { items: tenants } }
      return { status: 404, body: {} }
    })
    await router.push('/operator/tenants/t-acme')
    const w = mountView(TenantDetail)
    await flushPromises()
    await w.find('[data-test="suspend-open"]').trigger('click')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/suspend'))).toBe(false)
    dialogButton('Suspend').click()
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/operator/tenants/t-acme/suspend', expect.objectContaining({ method: 'POST' }))
    await w.find('[data-test="grant-open"]').trigger('click')
    await flushPromises()
    const posted = () => fetch.mock.calls.filter((c) => String(c[0]).endsWith('/operator/grants'))
    await type('[data-test="grant-dialog"] textarea[data-field="reason"]', 'short')
    dialogButton('Create grant').click()
    await flushPromises()
    expect(posted().length).toBe(0)
    expect(q('[data-test="grant-dialog"] [role=alert]').textContent).toMatch(/10 characters/)
    await type('[data-test="grant-dialog"] textarea[data-field="reason"]', 'incident INC-4242 investigation')
    dialogButton('Create grant').click()
    await flushPromises()
    expect(body(posted()[0])).toEqual({ tenant_id: 't-acme', reason: 'incident INC-4242 investigation', duration: '1h' })
    expect(w.find('[data-test="grant"]').text()).toContain('audited')
    w.unmount()
  })

  it('shows a client secret exactly once, masked with a reveal toggle', async () => {
    stubFetch((url, init) => {
      if (url.endsWith('/admin/clients') && init?.method === 'POST') return { status: 201, body: { client_id: 'c1', display_name: 'Backend', redirect_uris: ['https://x/cb'], public: false, client_secret: 'S3CRET' } }
      return { status: 200, body: [] }
    })
    await router.push('/admin/clients')
    const w = mountView(Clients)
    await flushPromises()
    await w.find('[data-test="client-open"]').trigger('click')
    await flushPromises()
    await type('[data-test="client-dialog"] input[data-field="display_name"]', 'Backend')
    await type('[data-test="client-dialog"] textarea[data-field="redirect_uris"]', 'ftp://x/cb')
    dialogButton('Register').click()
    await flushPromises()
    expect(q('[data-test="client-dialog"] [role=alert]').textContent).toMatch(/https/)
    await type('[data-test="client-dialog"] textarea[data-field="redirect_uris"]', 'https://x/cb')
    dialogButton('Register').click()
    await flushPromises()
    const secret = w.find('[data-test="client-secret"] input')
    expect((secret.element as HTMLInputElement).value).toBe('S3CRET')
    expect(secret.attributes('type')).toBe('password')
    expect(w.text()).not.toContain('S3CRET')
    await click('[data-test="created-dismiss"]')
    expect(w.find('[data-test="client-secret"]').exists()).toBe(false)
    w.unmount()
  })
})
