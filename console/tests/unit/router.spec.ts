import { beforeEach, describe, expect, it, vi } from 'vitest'
import { createPinia, setActivePinia } from 'pinia'
import { router } from '@/router'
import { useSession } from '@/stores/session'

describe('router guards', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
  })

  it('redirects anonymous users to sign-in with a return path', async () => {
    vi.stubGlobal('fetch', vi.fn(async () => new Response('{"reason":"unauthenticated"}', { status: 401 })))
    await router.push('/')
    await router.isReady()
    expect(router.currentRoute.value.name).toBe('signin')
    expect(router.currentRoute.value.query.next).toBe('/')
  })

  it('lets authenticated users through and enforces role/operator meta', async () => {
    const s = useSession()
    s.apply({ user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: ['member'] })
    router.addRoute({ path: '/admin-only', name: 'admin-only', component: { template: '<div />' }, meta: { roles: ['owner', 'admin'] } })
    router.addRoute({ path: '/ops-only', name: 'ops-only', component: { template: '<div />' }, meta: { operator: true } })
    await router.push('/')
    expect(router.currentRoute.value.name).toBe('home')
    await router.push('/admin-only')
    expect(router.currentRoute.value.name).toBe('forbidden')
    await router.push('/ops-only')
    expect(router.currentRoute.value.name).toBe('forbidden')
    s.roles = ['admin']
    s.operator = true
    await router.push('/admin-only')
    expect(router.currentRoute.value.name).toBe('admin-only')
    await router.push('/ops-only')
    expect(router.currentRoute.value.name).toBe('ops-only')
  })

  it('sends everyone to the outage page while the API is down', async () => {
    const s = useSession()
    s.status = 'outage'
    await router.push('/')
    expect(router.currentRoute.value.name).toBe('outage')
  })
})
