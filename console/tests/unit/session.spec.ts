import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { useSession } from '@/stores/session'

function mockFetch(status: number, body: unknown): void {
  vi.stubGlobal(
    'fetch',
    vi.fn(async () => new Response(JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })),
  )
}

describe('session store', () => {
  beforeEach(() => setActivePinia(createPinia()))

  it('becomes authenticated from /api/v1/session', async () => {
    mockFetch(200, { user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1', slug: 'acme', display_name: 'Acme' }, roles: ['admin'] })
    const s = useSession()
    await s.load()
    expect(s.signedIn).toBe(true)
    expect(s.hasAnyRole(['owner', 'admin'])).toBe(true)
    expect(s.hasRole('auditor')).toBe(false)
    expect(s.tenant?.slug).toBe('acme')
  })

  it('is anonymous on 401 and shares one in-flight request', async () => {
    mockFetch(401, { reason: 'unauthenticated' })
    const s = useSession()
    await Promise.all([s.load(), s.load()])
    expect(s.status).toBe('anonymous')
    expect(vi.mocked(fetch).mock.calls.length).toBe(1)
  })

  it('reports an outage on network failure and 5xx', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => { throw new TypeError('offline') }))
    const s = useSession()
    await s.load()
    expect(s.status).toBe('outage')
    mockFetch(503, {})
    await s.load(true)
    expect(s.status).toBe('outage')
  })

  it('sends the CSRF header on sign-out and resets', async () => {
    document.cookie = '__Host-csrf=tok123; Secure; Path=/'
    mockFetch(204, {})
    const s = useSession()
    s.apply({ user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: ['owner'] })
    await s.signOut()
    const init = vi.mocked(fetch).mock.calls[0]?.[1] as RequestInit
    expect((init.headers as Record<string, string>)['X-CSRF-Token']).toBe('tok123')
    expect(s.status).toBe('anonymous')
    expect(s.roles).toEqual([])
  })
})
