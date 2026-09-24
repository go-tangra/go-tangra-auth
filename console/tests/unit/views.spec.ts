import { beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { axe } from 'vitest-axe'
import AcceptInvitation from '@/views/AcceptInvitation.vue'
import MfaChallenge from '@/views/MfaChallenge.vue'
import MfaEnrol from '@/views/MfaEnrol.vue'
import ForgotPassword from '@/views/ForgotPassword.vue'
import ResetPassword from '@/views/ResetPassword.vue'
import Outage from '@/views/Outage.vue'
import Forbidden from '@/views/Forbidden.vue'
import NotFound from '@/views/NotFound.vue'
import Home from '@/views/Home.vue'
import { router } from '@/router'
import { useSignin } from '@/stores/signin'
import { useSession } from '@/stores/session'
import { body, mountView, stubFetch } from './helpers'

// T060: the bare (signed-out) views and the enrolment wizard on the kit —
// zod refusals inline, secret fields never autofilled, recovery codes legible
// and copyable, no inline styles, axe clean.
const noStyle = (w: ReturnType<typeof mountView>) => expect(w.find('[style]').exists()).toBe(false)

describe('console views on the kit (T060)', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    useSession().status = 'anonymous'
    await router.push({ name: 'signin' })
    await router.isReady()
  })

  it('accept invitation: password rules inline, confirm must match, secret fields masked with new-password autocomplete', async () => {
    const fetch = stubFetch((url) => (url.endsWith('/invitations/accept') ? { status: 200, body: { signed_in: true } } : { status: 200, body: { user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: [] } }))
    await router.push({ name: 'invite-accept', query: { token: 'tok' } })
    const w = mountView(AcceptInvitation)
    await flushPromises()
    const pw = w.find('[data-test="password"] input')
    expect(pw.attributes('type')).toBe('password')
    expect(pw.attributes('autocomplete')).toBe('new-password')
    await w.find('[data-test="name"] input').setValue('Ann')
    await pw.setValue('short')
    await w.find('[data-test="confirm"] input').setValue('short')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/invitations/accept'))).toBe(false)
    expect(w.find('[data-test="password"] [role=alert]').text()).toMatch(/at least 8/i)
    await pw.setValue('long-enough-password')
    await w.find('[data-test="confirm"] input').setValue('different')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.find('[data-test="confirm"] [role=alert]').text()).toMatch(/do not match/)
    await w.find('[data-test="confirm"] input').setValue('long-enough-password')
    await w.find('form').trigger('submit')
    await flushPromises()
    const call = fetch.mock.calls.find((c) => String(c[0]).endsWith('/invitations/accept'))
    expect(body(call)).toEqual({ token: 'tok', display_name: 'Ann', password: 'long-enough-password' })
    noStyle(w)
    expect((await axe(w.element as HTMLElement, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })).violations).toEqual([])
    w.unmount()
  })

  it('MFA challenge: TOTP or recovery code share one refusal message and the field is cleared and refocused', async () => {
    useSignin().challenge = 'ch-1'
    const fetch = stubFetch(() => ({ status: 401, body: { reason: 'invalid_code' } }))
    const w = mountView(MfaChallenge)
    await flushPromises()
    const code = () => w.find('[data-test="code"] input')
    expect(code().attributes('autocomplete')).toBe('one-time-code')
    await code().setValue('12')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/signin/mfa'))).toBe(false)
    expect(w.find('[data-test="code"] [role=alert]').text()).toMatch(/6-digit code or a recovery code/)
    await code().setValue('123456')
    await w.find('form').trigger('submit')
    await flushPromises()
    const totp = w.find('[data-test="error"]').text()
    expect((code().element as HTMLInputElement).value).toBe('')
    expect(document.activeElement).toBe(code().element)
    await code().setValue('ABCDE-12345')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.find('[data-test="error"]').text()).toBe(totp)
    expect(body(fetch.mock.calls.at(-1))).toEqual({ challenge: 'ch-1', code: 'ABCDE-12345' })
    noStyle(w)
    w.unmount()
  })

  it('MFA enrolment: QR + manual key, confirm, recovery codes legible and copyable, continue only after the saved checkbox', async () => {
    useSession().apply({ user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: [], mfa_setup_required: true })
    const fetch = stubFetch((url) => {
      if (url.endsWith('/me/mfa/enroll')) return { status: 200, body: { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/Freya:a@x.test?secret=JBSWY3DPEHPK3PXP' } }
      if (url.endsWith('/me/mfa/confirm')) return { status: 200, body: { recovery_codes: ['AAAAA-BBBBB', 'CCCCC-DDDDD'] } }
      return { status: 200, body: { user: { id: 'u1', email: 'a@x.test', mfa_enabled: true }, tenant: { id: 't1' }, roles: [] } }
    })
    const w = mountView(MfaEnrol)
    await vi.waitFor(() => expect(w.find('[data-test="qr"]').exists()).toBe(true))
    expect(w.find('[data-test="secret"]').text()).toBe('JBSWY3DPEHPK3PXP')
    await w.find('[data-test="code"] input').setValue('123456')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(body(fetch.mock.calls.find((c) => String(c[0]).endsWith('/me/mfa/confirm')))).toEqual({ code: '123456' })
    const codes = w.findAll('[data-test="recovery-codes"] li')
    expect(codes.map((c) => c.text())).toEqual(['AAAAA-BBBBB', 'CCCCC-DDDDD'])
    expect(w.find('[data-test="recovery-codes"]').classes()).toContain('font-mono')
    expect(w.find('button[aria-label="Copy all codes"]').exists()).toBe(true)
    // Continue refuses until the person confirms they saved the codes.
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(w.find('[data-test="saved"] [role=alert]').text()).toMatch(/saved the codes/)
    const box = w.find('[data-test="saved"] input').element as HTMLInputElement
    box.checked = true
    box.dispatchEvent(new Event('change'))
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/api/v1/session'))).toBe(true)
    noStyle(w)
    w.unmount()
  })

  it('forgot + reset: zod refusals inline, one neutral confirmation, reset posts the token and returns to sign-in', async () => {
    const fetch = stubFetch(() => ({ status: 202, body: {} }))
    const f = mountView(ForgotPassword)
    await f.find('form').trigger('submit')
    await flushPromises()
    expect(fetch).not.toHaveBeenCalled()
    // Only the email: a blank organisation is taken from the email domain.
    expect(f.findAll('[role=alert]').length).toBe(1)
    await f.find('[data-test="tenant"] input').setValue('acme')
    await f.find('[data-test="email"] input').setValue('a@x.test')
    await f.find('form').trigger('submit')
    await flushPromises()
    expect(f.find('[data-test="sent"]').text()).toMatch(/If an account exists/)
    noStyle(f)
    f.unmount()
    await router.push({ name: 'reset', query: { token: 'tok' } })
    const r = mountView(ResetPassword)
    await flushPromises()
    expect(r.find('[data-test="no-token"]').exists()).toBe(false)
    await r.find('[data-test="password"] input').setValue('long-enough-password')
    await r.find('[data-test="confirm"] input').setValue('long-enough-password')
    await r.find('form').trigger('submit')
    await flushPromises()
    expect(body(fetch.mock.calls.find((c) => String(c[0]).endsWith('/recovery/complete')))).toEqual({ token: 'tok', new_password: 'long-enough-password' })
    expect(router.currentRoute.value.name).toBe('signin')
    r.unmount()
  })

  it('outage, forbidden, not-found and home render on kit primitives without inline styles and axe clean', async () => {
    useSession().apply({ user: { id: 'u1', email: 'a@x.test', mfa_enabled: false }, tenant: { id: 't1', display_name: 'Acme' }, roles: ['owner'] })
    stubFetch(() => ({ status: 200, body: {} }))
    for (const view of [Outage, Forbidden, NotFound, Home]) {
      const w = mountView(view)
      await flushPromises()
      noStyle(w)
      expect((await axe(w.element as HTMLElement, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })).violations).toEqual([])
      w.unmount()
    }
  })
})
