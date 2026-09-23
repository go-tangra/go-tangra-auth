import { describe, expect, it } from 'vitest'
import { acceptInvitationSchema, auditFilterSchema, changePasswordSchema, clientSchema, grantSchema, groupSchema, inviteSchema, mfaChallengeSchema, policySchema, roleSchema, signInSchema, tenantSchema, totpSchema } from '@/schemas'

const bad = (r: { success: boolean; error?: { issues: { path: PropertyKey[]; message: string }[] } }) => (r.success ? [] : r.error!.issues.map((i) => i.path.join('.') + ':' + i.message))

describe('console schemas (T034)', () => {
  it('sign-in: slug grammar, e-mail, non-empty password; slug is lower-cased and trimmed', () => {
    expect(signInSchema.parse({ tenant: ' Acme ', email: 'a@x.test', password: 'pw' })).toEqual({ tenant: 'acme', email: 'a@x.test', password: 'pw' })
    expect(bad(signInSchema.safeParse({ tenant: 'Acme Corp', email: 'nope', password: '' }))).toEqual(expect.arrayContaining([expect.stringMatching(/^tenant:/), expect.stringMatching(/^email:/), expect.stringMatching(/^password:/)]))
    expect(signInSchema.safeParse({ tenant: '-acme', email: 'a@x.test', password: 'pw' }).success).toBe(false)
  })
  it('MFA: six digits or a XXXXX-XXXXX recovery code; strict TOTP elsewhere', () => {
    expect(mfaChallengeSchema.safeParse({ code: ' 123456 ' }).success).toBe(true)
    expect(mfaChallengeSchema.safeParse({ code: 'AB12C-9XYZ0' }).success).toBe(true)
    for (const code of ['12345', '1234567', 'ABCDE-', 'ABCDE-1234', 'abc def-12345', '']) expect(mfaChallengeSchema.safeParse({ code }).success, code).toBe(false)
    expect(totpSchema.safeParse({ code: 'AB12C-9XYZ0' }).success).toBe(false)
    expect(totpSchema.safeParse({ code: '000000' }).success).toBe(true)
  })
  it('accept invitation: policy minimum length and matching confirmation on the confirm field', () => {
    const s = acceptInvitationSchema(12)
    expect(bad(s.safeParse({ display_name: 'Ann', password: 'short', confirm: 'short' }))).toEqual(['password:At least 12 characters.'])
    expect(bad(s.safeParse({ display_name: 'Ann', password: 'long-enough-password', confirm: 'different' }))).toEqual(['confirm:The passwords do not match.'])
    expect(bad(s.safeParse({ display_name: '  ', password: 'long-enough-password', confirm: 'long-enough-password' }))[0]).toMatch(/^display_name:/)
    expect(s.safeParse({ display_name: 'Ann', password: 'long-enough-password', confirm: 'long-enough-password' }).success).toBe(true)
  })
  it('change password: current required, new obeys the minimum, confirm matches', () => {
    const s = changePasswordSchema(8)
    expect(bad(s.safeParse({ current_password: '', new_password: 'new-password', confirm: 'new-password' }))).toEqual(['current_password:Enter your current password.'])
    expect(bad(s.safeParse({ current_password: 'old', new_password: 'new-password', confirm: 'nope' }))).toEqual(['confirm:The passwords do not match.'])
  })
  it('invite: e-mail required, names optional, roles/groups default to empty arrays', () => {
    expect(inviteSchema.parse({ email: 'new@x.test' })).toEqual({ email: 'new@x.test', first_name: undefined, last_name: undefined, role_ids: [], group_ids: [] })
    expect(inviteSchema.safeParse({ email: 'nope' }).success).toBe(false)
    expect(inviteSchema.parse({ email: 'new@x.test', last_name: ' Kovač ', group_ids: ['g1'] })).toMatchObject({ last_name: 'Kovač', group_ids: ['g1'] })
  })
  it('role: slug grammar, reserved built-ins refused, permissions resource:action', () => {
    expect(roleSchema.safeParse({ slug: 'owner', display_name: 'X' }).success).toBe(false)
    expect(roleSchema.safeParse({ slug: 'Billing', display_name: 'X' }).success).toBe(false)
    expect(roleSchema.safeParse({ slug: 'billing', display_name: 'X', permissions: ['invoices'] }).success).toBe(false)
    expect(roleSchema.parse({ slug: 'billing', display_name: 'Billing' })).toEqual({ slug: 'billing', display_name: 'Billing', permissions: [] })
  })
  it('group: 1–64 characters trimmed, description optional → ""', () => {
    expect(groupSchema.parse({ name: ' Ops ' })).toEqual({ name: 'Ops', description: '' })
    expect(groupSchema.safeParse({ name: 'x'.repeat(65) }).success).toBe(false)
    expect(groupSchema.safeParse({ name: '   ' }).success).toBe(false)
  })
  it('policy: durations, bounds and idle ≤ session', () => {
    const ok = { session_lifetime: '8h', idle_timeout: '1h', access_token_lifetime: '15m', password_min_length: '12', mfa_required: undefined, lockout_threshold: 10, lockout_duration: '15m' }
    expect(policySchema.parse(ok)).toMatchObject({ password_min_length: 12, mfa_required: false })
    expect(bad(policySchema.safeParse({ ...ok, idle_timeout: '9h' }))).toEqual(['idle_timeout:At most the session lifetime.'])
    expect(bad(policySchema.safeParse({ ...ok, session_lifetime: '25h' }))).toEqual(['session_lifetime:At most 24h.'])
    expect(bad(policySchema.safeParse({ ...ok, access_token_lifetime: '16m' }))).toEqual(['access_token_lifetime:At most 15m.'])
    expect(bad(policySchema.safeParse({ ...ok, lockout_duration: '2h' }))).toEqual(['lockout_duration:Between 1m and 1h.'])
    expect(bad(policySchema.safeParse({ ...ok, lockout_threshold: 2 }))).toEqual(['lockout_threshold:Between 3 and 20.'])
    expect(bad(policySchema.safeParse({ ...ok, session_lifetime: 'eight hours' }))[0]).toMatch(/^session_lifetime:Use a duration/)
    expect(bad(policySchema.safeParse({ ...ok, password_min_length: 7 }))).toEqual(['password_min_length:At least 8.'])
  })
  it('client: https redirect URIs one per line (http only for localhost); public defaults to true', () => {
    expect(clientSchema.parse({ display_name: 'Backend', redirect_uris: 'https://x/cb\n\nhttp://localhost:3000/cb\n' })).toEqual({ display_name: 'Backend', redirect_uris: ['https://x/cb', 'http://localhost:3000/cb'], public: true })
    expect(bad(clientSchema.safeParse({ display_name: 'Backend', redirect_uris: 'http://x/cb' }))).toEqual(['redirect_uris.0:Redirect URIs must be https (http only for localhost).'])
    expect(bad(clientSchema.safeParse({ display_name: 'Backend', redirect_uris: '' }))).toEqual(['redirect_uris:Enter at least one redirect URI.'])
  })
  it('tenant + grant: slug, owner e-mail, reason ≥ 10 characters, duration from the fixed set', () => {
    expect(tenantSchema.parse({ slug: 'Globex', display_name: 'Globex', owner_email: 'o@globex.test' }).slug).toBe('globex')
    expect(tenantSchema.safeParse({ slug: 'Globex Inc', display_name: 'Globex', owner_email: 'o@globex.test' }).success).toBe(false)
    expect(grantSchema.safeParse({ reason: 'short', duration: '1h' }).success).toBe(false)
    expect(grantSchema.safeParse({ reason: 'incident INC-1 follow-up', duration: '3h' }).success).toBe(false)
    expect(grantSchema.parse({ reason: '  incident INC-1 follow-up ', duration: '15m' })).toEqual({ reason: 'incident INC-1 follow-up', duration: '15m' })
  })
  it('audit filter: known event types only; free-text user id capped', () => {
    expect(auditFilterSchema.safeParse({ event_type: 'made_up_event' }).success).toBe(false)
    expect(auditFilterSchema.safeParse({ user_id: 'x'.repeat(65) }).success).toBe(false)
    expect(auditFilterSchema.parse({})).toEqual({ event_type: undefined, user_id: undefined, from: undefined, to: undefined })
  })
})
