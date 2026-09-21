import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import Tenants from '@/views/operator/Tenants.vue'
import TenantDetail from '@/views/operator/TenantDetail.vue'
import Clients from '@/views/admin/Clients.vue'
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
const tenants = [
  { id: 't-platform', slug: 'platform', display_name: 'Platform', status: 'active', kind: 'platform', created_at: '2026-01-01T00:00:00Z' },
  { id: 't-acme', slug: 'acme', display_name: 'Acme', status: 'active', kind: 'customer', created_at: '2026-01-02T00:00:00Z' },
]
const plugins = () => [createVuetify({ components, directives }), router]

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
    const w = mount(Tenants, { global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    expect(w.findAll('[data-test="tenant-row"]').length).toBe(2)
    await w.find('[data-test="create-open"]').trigger('click')
    await flushPromises()
    const q = (sel: string) => document.querySelector(sel) as HTMLInputElement
    const set = async (sel: string, v: string) => {
      q(sel).value = v
      q(sel).dispatchEvent(new Event('input'))
      await flushPromises()
    }
    const btn = () => document.querySelector('[data-test="create"]') as HTMLButtonElement
    expect(btn().disabled).toBe(true)
    await set('[data-test="slug"] input', 'Globex Inc')
    await set('[data-test="name"] input', 'Globex')
    await set('[data-test="owner"] input', 'owner@globex.test')
    expect(btn().disabled).toBe(true)
    await set('[data-test="slug"] input', 'globex')
    expect(btn().disabled).toBe(false)
    btn().click()
    await flushPromises()
    const call = fetch.mock.calls.find((c) => String(c[0]) === '/api/v1/operator/tenants' && (c[1] as RequestInit).method === 'POST')
    expect(JSON.parse(String((call?.[1] as RequestInit).body))).toEqual({ slug: 'globex', display_name: 'Globex', owner_email: 'owner@globex.test' })
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
    const w = mount(TenantDetail, { global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    await w.find('[data-test="suspend-open"]').trigger('click')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/suspend'))).toBe(false)
    ;(document.querySelector('[data-test="suspend-confirm"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/operator/tenants/t-acme/suspend', expect.objectContaining({ method: 'POST' }))
    await w.find('[data-test="grant-open"]').trigger('click')
    await flushPromises()
    const reason = document.querySelector('[data-test="reason"] textarea') as HTMLTextAreaElement
    const create = () => document.querySelector('[data-test="grant-create"]') as HTMLButtonElement
    reason.value = 'short'
    reason.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(create().disabled).toBe(true)
    reason.value = 'incident INC-4242 investigation'
    reason.dispatchEvent(new Event('input'))
    await flushPromises()
    expect(create().disabled).toBe(false)
    create().click()
    await flushPromises()
    const call = fetch.mock.calls.find((c) => String(c[0]).endsWith('/operator/grants'))
    expect(JSON.parse(String((call?.[1] as RequestInit).body))).toEqual({ tenant_id: 't-acme', reason: 'incident INC-4242 investigation', duration: '1h' })
    expect(w.find('[data-test="grant"]').text()).toContain('audited')
    w.unmount()
  })

  it('shows a client secret exactly once', async () => {
    stubFetch((url, init) => {
      if (url.endsWith('/admin/clients') && init?.method === 'POST') return { status: 201, body: { client_id: 'c1', display_name: 'Backend', redirect_uris: ['https://x/cb'], public: false, client_secret: 'S3CRET' } }
      return { status: 200, body: [] }
    })
    await router.push('/admin/clients')
    const w = mount(Clients, { global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    await w.find('[data-test="client-open"]').trigger('click')
    await flushPromises()
    const q = (sel: string) => document.querySelector(sel) as HTMLInputElement | HTMLTextAreaElement
    q('[data-test="client-name"] input').value = 'Backend'
    q('[data-test="client-name"] input').dispatchEvent(new Event('input'))
    q('[data-test="client-uris"] textarea').value = 'https://x/cb'
    q('[data-test="client-uris"] textarea').dispatchEvent(new Event('input'))
    await flushPromises()
    ;(document.querySelector('[data-test="client-create"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(w.find('[data-test="client-secret"]').text()).toBe('S3CRET')
    await w.find('[data-test="created-dismiss"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="client-secret"]').exists()).toBe(false)
    w.unmount()
  })
})
