import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { axe } from 'vitest-axe'
import AcceptInvitation from '@/views/AcceptInvitation.vue'
import ResetPassword from '@/views/ResetPassword.vue'
import Account from '@/views/Account.vue'
import { router } from '@/router'
import { useSession } from '@/stores/session'
import { ApiError } from '@/api/client'
import { acceptInvitationSchema } from '@/schemas'
import { codePoints, evaluate, isTrivial, parseRequirements, PASSWORD_FLOOR, refusalMessage, refusedRule, summary, type PasswordRequirements } from '@/password/rules'
import { body, mountView, stubFetch } from './helpers'

const RULES: PasswordRequirements = { min_length: 12, max_length: 64, reject_trivial: true }
const state = (w: ReturnType<typeof mountView>) => Object.fromEntries(w.findAll('[data-test="pw-rules"] li').map((li) => [li.attributes('data-rule'), li.attributes('data-state')]))
const axeClean = async (el: Element) => expect((await axe(el as HTMLElement, { rules: { 'color-contrast': { enabled: false }, region: { enabled: false } } })).violations).toEqual([])

describe('password rules (client mirror of the server policy)', () => {
  it('counts code points, treats blank and one repeated character as trivial, and evaluates the checklist', () => {
    expect(codePoints('😀😀')).toBe(2)
    expect(isTrivial('   ')).toBe(true)
    expect(isTrivial('éééé')).toBe(true)
    expect(isTrivial('😀😀😀')).toBe(true)
    expect(isTrivial('aaab')).toBe(false)
    expect(evaluate(RULES, 'short', 'short').map((r) => [r.key, r.met])).toEqual([['min_length', false], ['max_length', true], ['reject_trivial', true], ['match', true]])
    expect(evaluate(RULES, '', '').find((r) => r.key === 'match')?.met).toBe(false)
    expect(evaluate({ ...RULES, reject_trivial: false }, 'x', 'x').map((r) => r.key)).toEqual(['min_length', 'max_length', 'match'])
    expect(summary(RULES)).toBe('Use 12 to 64 characters, not blank or a single repeated character.')
  })
  it('accepts only well-formed requirements', () => {
    expect(parseRequirements(RULES)).toEqual(RULES)
    for (const bad of [null, {}, { user: {} }, { ...RULES, min_length: '12' }, { ...RULES, min_length: 99 }, { ...RULES, reject_trivial: 1 }]) expect(parseRequirements(bad)).toBeUndefined()
  })
  it('maps a password_policy refusal to the rule it names and never to anything else', () => {
    expect(refusedRule(new ApiError(400, 'password_policy', { rule: 'min_length' }))).toBe('min_length')
    expect(refusedRule(new ApiError(400, 'password_policy', { rule: 'something_new' }))).toBeUndefined()
    expect(refusedRule(new ApiError(400, 'invalid_token', { rule: 'min_length' }))).toBeUndefined()
    expect(refusalMessage(RULES, new ApiError(400, 'password_policy', { rule: 'reject_trivial' }))).toMatch(/refused this password: must not be blank or a single repeated character/)
    expect(refusalMessage(RULES, new ApiError(400, 'password_policy'))).toMatch(/does not meet the organisation policy/)
    expect(refusalMessage(RULES, new Error('x'))).toBeUndefined()
  })
  it('the schema follows rules that arrive after the form is built', () => {
    let rules = PASSWORD_FLOOR
    const s = acceptInvitationSchema(() => rules)
    const v = { display_name: 'Ann', password: 'ten-chars!', confirm: 'ten-chars!' }
    expect(s.safeParse(v).success).toBe(true)
    rules = RULES
    expect(s.safeParse(v).success).toBe(false)
    expect(s.safeParse({ ...v, password: 'zzzzzzzzzzzz', confirm: 'zzzzzzzzzzzz' }).error?.issues[0]?.message).toMatch(/single repeated character/)
  })
})

describe('password requirements on the set-password pages', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    useSession().status = 'anonymous'
    await router.push({ name: 'signin' })
    await router.isReady()
  })

  it('invitation: loads the organisation rules with the token in the body, checks them live and gates submit', async () => {
    const fetch = stubFetch((url) => {
      if (url.endsWith('/invitations/password-policy')) return { status: 200, body: RULES }
      if (url.endsWith('/invitations/accept')) return { status: 200, body: { signed_in: true } }
      return { status: 200, body: { user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: [] } }
    })
    await router.push({ name: 'invite-accept', query: { token: 'tok' } })
    const w = mountView(AcceptInvitation)
    await flushPromises()
    const lookup = fetch.mock.calls.find((c) => String(c[0]).endsWith('/invitations/password-policy'))
    expect(String(lookup?.[0])).not.toContain('tok')
    expect(body(lookup)).toEqual({ token: 'tok' })
    // The rules are listed and the password field is described by them.
    expect(w.find('[data-test="pw-rules"]').text()).toContain('At least 12 characters')
    const pw = w.find('[data-test="password"] input')
    const hint = document.getElementById(pw.attributes('aria-describedby') ?? '')
    expect(hint?.textContent).toBe('Use 12 to 64 characters, not blank or a single repeated character.')
    const submit = w.find('[data-test="submit"]')
    expect(submit.attributes('disabled')).toBeDefined()
    expect(state(w)).toEqual({ min_length: 'pending', max_length: 'met', reject_trivial: 'pending', match: 'pending' })
    // Live: each keystroke re-evaluates; the status line is a polite live region.
    await w.find('[data-test="name"] input').setValue('Ann')
    await pw.setValue('aaaaaaaaaaaa')
    expect(state(w)).toMatchObject({ min_length: 'met', reject_trivial: 'pending' })
    await pw.setValue('long-enough-password')
    await w.find('[data-test="confirm"] input').setValue('long-enough-passwor')
    expect(state(w)).toEqual({ min_length: 'met', max_length: 'met', reject_trivial: 'met', match: 'pending' })
    const status = w.find('[data-test="pw-rules-status"]')
    expect(status.attributes('aria-live')).toBe('polite')
    expect(status.text()).toBe('3 of 4 password requirements met.')
    expect(submit.attributes('disabled')).toBeDefined()
    await w.find('[data-test="confirm"] input').setValue('long-enough-password')
    expect(status.text()).toBe('4 of 4 password requirements met.')
    expect(submit.attributes('disabled')).toBeUndefined()
    await axeClean(w.element)
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(body(fetch.mock.calls.find((c) => String(c[0]).endsWith('/invitations/accept')))).toEqual({ token: 'tok', display_name: 'Ann', password: 'long-enough-password' })
    w.unmount()
  })

  it('invitation: a server refusal marks the rule it names and never echoes the password', async () => {
    stubFetch((url) => {
      if (url.endsWith('/invitations/password-policy')) return { status: 200, body: { ...RULES, min_length: 8 } }
      return { status: 400, body: { reason: 'password_policy', detail: { rule: 'reject_trivial' } } }
    })
    await router.push({ name: 'invite-accept', query: { token: 'tok' } })
    const w = mountView(AcceptInvitation)
    await flushPromises()
    await w.find('[data-test="name"] input').setValue('Ann')
    await w.find('[data-test="password"] input').setValue('Secret-Value-42')
    await w.find('[data-test="password"] input').trigger('blur') // touched: the cleared field revalidates
    await w.find('[data-test="confirm"] input').setValue('Secret-Value-42')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(state(w).reject_trivial).toBe('refused')
    expect(w.find('[data-test="password"] [role=alert]').text()).toMatch(/refused this password: must not be blank or a single repeated character/)
    expect(w.find('[data-test="pw-rules-status"]').text()).toMatch(/refused: not blank or a single repeated character/)
    expect(document.body.innerHTML).not.toContain('Secret-Value-42')
    expect((w.find('[data-test="password"] input').element as HTMLInputElement).value).toBe('')
    // Typing a new password clears the server's verdict.
    await w.find('[data-test="password"] input').setValue('another-password')
    expect(state(w).reject_trivial).toBe('met')
    w.unmount()
  })

  it('invitation: an expired link says so before the person types anything', async () => {
    stubFetch(() => ({ status: 400, body: { reason: 'invalid_token' } }))
    await router.push({ name: 'invite-accept', query: { token: 'old' } })
    const w = mountView(AcceptInvitation)
    await flushPromises()
    expect(w.find('[data-test="invalid-token"]').text()).toMatch(/invalid or has expired/)
    expect(w.find('form').exists()).toBe(false)
    w.unmount()
  })

  it('invitation: without the organisation rules the platform floor is shown and the server decides', async () => {
    stubFetch(() => ({ status: 503, body: { reason: 'unavailable' } }))
    await router.push({ name: 'invite-accept', query: { token: 'tok' } })
    const w = mountView(AcceptInvitation)
    await flushPromises()
    expect(w.find('[data-test="pw-rules"]').text()).toContain('At least 8 characters')
    expect(w.find('form').exists()).toBe(true)
    w.unmount()
  })

  it('reset: the reset token loads the rules and a min_length refusal is named', async () => {
    const fetch = stubFetch((url) => {
      if (url.endsWith('/recovery/password-policy')) return { status: 200, body: { ...RULES, min_length: 10 } }
      return { status: 400, body: { reason: 'password_policy', detail: { rule: 'min_length' } } }
    })
    await router.push({ name: 'reset', query: { token: 'rtok' } })
    const w = mountView(ResetPassword)
    await flushPromises()
    expect(body(fetch.mock.calls.find((c) => String(c[0]).endsWith('/recovery/password-policy')))).toEqual({ token: 'rtok' })
    expect(w.find('[data-test="pw-rules"]').text()).toContain('At least 10 characters')
    await w.find('[data-test="password"] input').setValue('long-enough-password')
    await w.find('[data-test="confirm"] input').setValue('long-enough-password')
    await w.find('form').trigger('submit')
    await flushPromises()
    expect(state(w).min_length).toBe('refused')
    expect(w.find('[data-test="password"] [role=alert]').text()).toMatch(/at least 10 characters/)
    w.unmount()
  })

  it('change password: the signed-in tenant rules are shown and gate the submit button', async () => {
    useSession().apply({ user: { id: 'u1', email: 'a@x.test', mfa_enabled: false }, tenant: { id: 't1' }, roles: [] })
    await router.push('/security')
    const fetch = stubFetch((url) => (url.endsWith('/me/password-policy') ? { status: 200, body: { ...RULES, min_length: 14 } } : { status: 200, body: {} }))
    const w = mountView(Account)
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/api/v1/me/password-policy') && ((c[1] as RequestInit | undefined)?.method ?? 'GET') === 'GET')).toBe(true)
    expect(w.find('[data-test="password-card"] [data-test="pw-rules"]').text()).toContain('At least 14 characters')
    await w.find('[data-test="new"] input').setValue('thirteen-char')
    await w.find('[data-test="confirm"] input').setValue('thirteen-char')
    expect(w.find('[data-test="pw-submit"]').attributes('disabled')).toBeDefined()
    await w.find('[data-test="new"] input').setValue('fourteen-chars')
    await w.find('[data-test="confirm"] input').setValue('fourteen-chars')
    expect(w.find('[data-test="pw-submit"]').attributes('disabled')).toBeUndefined()
    w.unmount()
  })
})
