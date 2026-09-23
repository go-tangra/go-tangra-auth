import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import SignIn from '@/views/SignIn.vue'
import MfaChallenge from '@/views/MfaChallenge.vue'
import { router } from '@/router'
import { safeNext, useSignin } from '@/stores/signin'
import { useSession } from '@/stores/session'
import { mountView, stubFetch } from './helpers'

describe('safeNext', () => {
  it('accepts internal paths and rejects external, malformed or sign-in targets', () => {
    expect(safeNext('/admin/users')).toBe('/admin/users')
    expect(safeNext('/security?tab=1')).toBe('/security?tab=1')
    expect(safeNext('https://evil.test')).toBe('/')
    expect(safeNext('//evil.test')).toBe('/')
    expect(safeNext('/a\\b')).toBe('/')
    expect(safeNext(undefined)).toBe('/')
    // A next that points back at sign-in would bounce the person out again.
    expect(safeNext('/signin')).toBe('/')
    expect(safeNext('/console/signin')).toBe('/')
    expect(safeNext('/console/signin?next=%2Fconsole%2Fsignin')).toBe('/')
  })
})

async function mountSignIn(next?: string) {
  await router.push(next ? { name: 'signin', query: { next } } : { name: 'signin' })
  await router.isReady()
  return mountView(SignIn)
}
type W = ReturnType<typeof mountView>
async function fill(w: W, tenant: string, email: string, password: string) {
  await w.find('[data-test="tenant"] input').setValue(tenant)
  await w.find('[data-test="email"] input').setValue(email)
  await w.find('[data-test="password"] input').setValue(password)
}

describe('sign-in view', () => {
  beforeEach(() => {
    setActivePinia(createPinia())
    useSession().status = 'anonymous'
  })

  it('validates the form with zod before posting anything', async () => {
    const fetch = stubFetch(() => ({ status: 401, body: { reason: 'unauthenticated' } }))
    const posted = () => fetch.mock.calls.filter((c) => String(c[0]).endsWith('/api/v1/signin')).length
    const w = await mountSignIn()
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(posted()).toBe(0)
    expect(w.findAll('[role=alert]').length).toBeGreaterThanOrEqual(3)
    await fill(w, 'Acme Corp', 'alice@x.test', 'pw')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(posted()).toBe(0) // slug grammar
    expect(w.find('[data-test="tenant"] [role=alert]').text()).toMatch(/lowercase/)
    await fill(w, 'acme', 'not-an-email', 'pw')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(posted()).toBe(0)
    expect(w.find('[data-test="email"] [role=alert]').exists()).toBe(true)
    await fill(w, 'acme', 'alice@x.test', 'pw')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(posted()).toBe(1)
    w.unmount()
  })

  it('resolves the organisation on blur using the slug only', async () => {
    const fetch = stubFetch((url) => (url.includes('/api/v1/tenants/resolve') ? { status: 200, body: { slug: 'acme', display_name: 'Acme Corp' } } : { status: 401, body: {} }))
    const w = await mountSignIn()
    await w.find('[data-test="tenant"] input').setValue('acme')
    await w.find('[data-test="tenant"] input').trigger('blur')
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/tenants/resolve?slug=acme', expect.anything())
    expect(w.text()).toContain('Acme Corp')
    w.unmount()
  })

  it('renders one generic message for every credential failure', async () => {
    let attempt = 0
    stubFetch((url) => {
      if (url.endsWith('/api/v1/signin')) {
        attempt++
        return { status: 401, body: { reason: 'invalid_credentials' } }
      }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = await mountSignIn()
    await fill(w, 'acme', 'nobody@x.test', 'pw')
    await w.find('form').trigger('submit')
    await flushPromises()
    const first = w.find('[data-test="error"]').text()
    await fill(w, 'acme', 'alice@x.test', 'wrong')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(attempt).toBe(2)
    expect(w.find('[data-test="error"]').text()).toBe(first)
    expect(first).not.toMatch(/unknown|does not exist|no account|wrong password|incorrect password|suspended/i)
    expect((w.find('[data-test="password"] input').element as HTMLInputElement).value).toBe('')
    w.unmount()
  })

  it('shows lockout and rate-limit messages distinctly', async () => {
    stubFetch(() => ({ status: 423, body: { reason: 'locked' } }))
    const w = await mountSignIn()
    await fill(w, 'acme', 'alice@x.test', 'pw')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.find('[data-test="error"]').text()).toMatch(/locked/i)
    w.unmount()
  })

  it('routes to the MFA step, keeping the challenge out of the URL', async () => {
    stubFetch((url) => (url.endsWith('/api/v1/signin') ? { status: 200, body: { mfa_required: true, challenge: 'ch-1' } } : { status: 404, body: {} }))
    const w = await mountSignIn('/sessions')
    await fill(w, 'acme', 'mfa@x.test', 'pw')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(router.currentRoute.value.name).toBe('signin-mfa')
    expect(router.currentRoute.value.fullPath).not.toContain('ch-1')
    const signin = useSignin()
    expect(signin.challenge).toBe('ch-1')
    expect(signin.next).toBe('/sessions')
    w.unmount()
    // Completing the challenge posts it and finishes the sign-in.
    const fetch = stubFetch((url) => {
      if (url.endsWith('/api/v1/signin/mfa')) return { status: 200, body: { signed_in: true } }
      if (url.endsWith('/api/v1/session')) return { status: 200, body: { user: { id: 'u1', email: 'mfa@x.test' }, tenant: { id: 't1' }, roles: [] } }
      return { status: 404, body: {} }
    })
    const m = mountView(MfaChallenge)
    await m.find('[data-test="code"] input').setValue('123456')
    await m.find('form').trigger('submit')
    await flushPromises()
    const call = fetch.mock.calls.find((c) => String(c[0]).endsWith('/api/v1/signin/mfa'))
    expect(JSON.parse(String((call?.[1] as RequestInit).body))).toEqual({ challenge: 'ch-1', code: '123456' })
    expect(useSession().signedIn).toBe(true)
    await vi.waitFor(() => expect(router.currentRoute.value.path).toBe('/sessions'))
    m.unmount()
  })

  it('never returns to a foreign origin after sign-in', () => {
    const signin = useSignin()
    expect(signin.messageFor(new Error('x'))).toMatch(/not available/)
    signin.next = '/'
  })
})
