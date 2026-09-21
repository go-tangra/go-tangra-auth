import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { createVuetify } from 'vuetify'
import * as components from 'vuetify/components'
import * as directives from 'vuetify/directives'
import Account from '@/views/Account.vue'
import Sessions from '@/views/Sessions.vue'
import { router } from '@/router'
import { useSession } from '@/stores/session'

vi.mock('qrcode', () => ({ default: { toDataURL: vi.fn(async (uri: string) => 'data:image/png;base64,' + btoa(uri)) } }))

type Reply = { status: number; body: unknown }
function stubFetch(handler: (url: string, init?: RequestInit) => Reply) {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const { status, body } = handler(String(input), init)
    return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fn)
  return fn
}
const plugins = () => [createVuetify({ components, directives }), router]

describe('account security', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    useSession().apply({ user: { id: 'u1', email: 'a@x.test', mfa_enabled: false }, tenant: { id: 't1' }, roles: [] })
    await router.push('/security')
    await router.isReady()
  })

  it('changes the password and reports the outcome', async () => {
    const fetch = stubFetch((url) => (url.endsWith('/me/password') ? { status: 204, body: null } : { status: 200, body: {} }))
    const w = mount(Account, { global: { plugins: plugins() }, attachTo: document.body })
    await w.find('[data-test="current"] input').setValue('old-password')
    await w.find('[data-test="new"] input').setValue('new-password-long')
    await w.find('[data-test="confirm"] input').setValue('different')
    await w.find('[data-test="password-card"] form').trigger('submit')
    await flushPromises()
    expect(w.find('[data-test="pw-error"]').text()).toMatch(/do not match/)
    await w.find('[data-test="current"] input').setValue('old-password')
    await w.find('[data-test="new"] input').setValue('new-password-long')
    await w.find('[data-test="confirm"] input').setValue('new-password-long')
    await w.find('[data-test="password-card"] form').trigger('submit')
    await flushPromises()
    const call = fetch.mock.calls.find((c) => String(c[0]).endsWith('/api/v1/me/password'))
    expect(JSON.parse(String((call?.[1] as RequestInit).body))).toEqual({ current_password: 'old-password', new_password: 'new-password-long' })
    expect(w.find('[data-test="pw-done"]').exists()).toBe(true)
    w.unmount()
  })

  it('runs the enrolment wizard: QR from otpauth, confirm, recovery codes shown once', async () => {
    stubFetch((url) => {
      if (url.endsWith('/me/mfa/enroll')) return { status: 200, body: { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/Freya:a@x.test?secret=JBSWY3DPEHPK3PXP' } }
      if (url.endsWith('/me/mfa/confirm')) return { status: 200, body: { recovery_codes: ['AAAAA-BBBBB', 'CCCCC-DDDDD'] } }
      if (url.endsWith('/api/v1/session')) return { status: 200, body: { user: { id: 'u1', email: 'a@x.test', mfa_enabled: true }, tenant: { id: 't1' }, roles: [] } }
      return { status: 404, body: {} }
    })
    const w = mount(Account, { global: { plugins: plugins() }, attachTo: document.body })
    await w.find('[data-test="enrol"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="qr"]').attributes('src')).toContain('data:image/png')
    expect(w.find('[data-test="secret"]').text()).toBe('JBSWY3DPEHPK3PXP')
    await w.find('[data-test="code"] input').setValue('123456')
    await w.find('[data-test="mfa-card"] form').trigger('submit')
    await flushPromises()
    expect(w.findAll('[data-test="recovery-codes"] li').length).toBe(2)
    await w.find('[data-test="codes-dismiss"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="recovery-codes"]').exists()).toBe(false)
    expect(w.find('[data-test="disable"]').exists()).toBe(true)
    w.unmount()
  })

  it('explains a policy-locked second factor', async () => {
    useSession().apply({ user: { id: 'u1', email: 'a@x.test', mfa_enabled: true }, tenant: { id: 't1' }, roles: [] })
    stubFetch(() => ({ status: 403, body: { reason: 'mfa_required' } }))
    const w = mount(Account, { global: { plugins: plugins() }, attachTo: document.body })
    await w.find('[data-test="disable-code"] input').setValue('123456')
    await w.find('[data-test="disable"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="mfa-notice"]').text()).toMatch(/requires a second factor/)
    w.unmount()
  })

  it('revokes another session from the list', async () => {
    const fetch = stubFetch((url) => {
      if (url.endsWith('/revoke')) return { status: 204, body: null }
      return { status: 200, body: [{ id: 's1', current: true, user_agent: 'me' }, { id: 's2', current: false, user_agent: 'other' }] }
    })
    await router.push('/sessions')
    const w = mount(Sessions, { global: { plugins: plugins() }, attachTo: document.body })
    await flushPromises()
    expect(w.findAll('[data-test="session"]').length).toBe(1)
    await w.find('[data-test="revoke"]').trigger('click')
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/sessions/s2/revoke', expect.objectContaining({ method: 'POST' }))
    w.unmount()
  })

  it('gates the console behind enrolment when the tenant requires it', async () => {
    useSession().apply({ user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: [], mfa_setup_required: true })
    await router.push('/')
    expect(router.currentRoute.value.name).toBe('mfa-enrol')
  })
})
