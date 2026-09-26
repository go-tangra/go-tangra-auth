import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import { ApiError } from '@/api/client'
import {
  b64urlDecode,
  b64urlEncode,
  credentialJSON,
  creationOptions,
  hostMatches,
  requestOptions,
  webAuthnMessage,
  webAuthnSupported,
} from '@/composables/useWebAuthn'
import Account from '@/views/Account.vue'
import MfaEnrol from '@/views/MfaEnrol.vue'
import MfaChallenge from '@/views/MfaChallenge.vue'
import SecurityKeys from '@/components/SecurityKeys.vue'
import UserDetail from '@/views/admin/UserDetail.vue'
import { router } from '@/router'
import { useSession } from '@/stores/session'
import { useSignin } from '@/stores/signin'
import { body, mountView, stubFetch } from './helpers'

const bytes = (...b: number[]) => new Uint8Array(b).buffer
const creation = {
  publicKey: {
    challenge: 'AQIDBA',
    rp: { id: 'localhost', name: 'Tangra' },
    user: { id: 'BQYH', name: 'a@x.test', displayName: 'Alice' },
    pubKeyCredParams: [{ type: 'public-key', alg: -7 }],
    excludeCredentials: [{ type: 'public-key', id: 'CAkK' }],
    attestation: 'none',
  },
}
const request = { publicKey: { challenge: 'AQIDBA', rpId: 'localhost', allowCredentials: [{ type: 'public-key', id: 'CAkK', transports: ['usb'] }] } }

/** A credential as a browser without toJSON() returns it. */
function rawCredential(kind: 'create' | 'get') {
  const response =
    kind === 'create'
      ? { clientDataJSON: bytes(1), attestationObject: bytes(2), getTransports: () => ['usb'] }
      : { clientDataJSON: bytes(1), authenticatorData: bytes(3), signature: bytes(4), userHandle: bytes(5) }
  return { id: 'CAkK', rawId: bytes(8, 9, 10), type: 'public-key', authenticatorAttachment: 'cross-platform', response, getClientExtensionResults: () => ({}) }
}

let create: ReturnType<typeof vi.fn>
let get: ReturnType<typeof vi.fn>
function stubWebAuthn(native = false) {
  class PKC {}
  if (native) {
    Object.assign(PKC, {
      parseCreationOptionsFromJSON: vi.fn((o: unknown) => ({ parsed: o })),
      parseRequestOptionsFromJSON: vi.fn((o: unknown) => ({ parsed: o })),
    })
  }
  vi.stubGlobal('PublicKeyCredential', PKC)
  create = vi.fn(async () => rawCredential('create'))
  get = vi.fn(async () => rawCredential('get'))
  Object.defineProperty(navigator, 'credentials', { value: { create, get }, configurable: true })
}

describe('useWebAuthn', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('converts between base64url and bytes', () => {
    expect(b64urlEncode(bytes(1, 2, 3, 4))).toBe('AQIDBA')
    expect(b64urlEncode(new Uint8Array([251, 255]))).toBe('-_8')
    expect(Array.from(new Uint8Array(b64urlDecode('-_8')))).toEqual([251, 255])
  })

  it('decodes options without parse*FromJSON and encodes the credential without toJSON', () => {
    stubWebAuthn(false)
    const c = creationOptions(creation).publicKey!
    expect(Array.from(new Uint8Array(c.challenge as ArrayBuffer))).toEqual([1, 2, 3, 4])
    expect(Array.from(new Uint8Array(c.user.id as ArrayBuffer))).toEqual([5, 6, 7])
    expect(Array.from(new Uint8Array(c.excludeCredentials![0]!.id as ArrayBuffer))).toEqual([8, 9, 10])
    const r = requestOptions(request).publicKey!
    expect(Array.from(new Uint8Array(r.allowCredentials![0]!.id as ArrayBuffer))).toEqual([8, 9, 10])
    const reg = credentialJSON(rawCredential('create') as unknown as PublicKeyCredential)
    expect(reg).toEqual({ id: 'CAkK', rawId: 'CAkK', type: 'public-key', authenticatorAttachment: 'cross-platform', clientExtensionResults: {}, response: { clientDataJSON: 'AQ', attestationObject: 'Ag', transports: ['usb'] } })
    const asr = credentialJSON(rawCredential('get') as unknown as PublicKeyCredential)
    expect(asr.response).toEqual({ clientDataJSON: 'AQ', authenticatorData: 'Aw', signature: 'BA', userHandle: 'BQ' })
  })

  it('prefers the native JSON helpers when the browser has them', () => {
    stubWebAuthn(true)
    expect(creationOptions(creation).publicKey).toEqual({ parsed: creation.publicKey })
    expect(requestOptions(request).publicKey).toEqual({ parsed: request.publicKey })
    const cred = { toJSON: () => ({ id: 'native' }) } as unknown as PublicKeyCredential
    expect(credentialJSON(cred)).toEqual({ id: 'native' })
  })

  it('explains an unsupported browser, a cancelled prompt and the wrong address', () => {
    expect(webAuthnSupported()).toBe(false)
    expect(webAuthnMessage(new Error('x'))).toMatch(/could not/)
    stubWebAuthn()
    expect(webAuthnSupported()).toBe(true)
    expect(webAuthnMessage(new DOMException('no', 'NotAllowedError'))).toMatch(/cancelled or timed out/)
    expect(webAuthnMessage(new DOMException('dup', 'InvalidStateError'))).toMatch(/already registered/)
    expect(webAuthnMessage(new DOMException('rp', 'SecurityError'), 'portal.example.org')).toMatch(/portal\.example\.org/)
    expect(webAuthnMessage(new ApiError(401, 'key_flagged'))).toMatch(/possibly cloned/)
    expect(webAuthnMessage(new ApiError(423, 'locked'))).toMatch(/locked/)
    expect(hostMatches('localhost', 'localhost')).toBe(true)
    expect(hostMatches('example.org', 'portal.example.org')).toBe(true)
    expect(hostMatches('example.org', 'evil-example.org')).toBe(false)
    expect(hostMatches('portal.example.org', '10.0.0.5')).toBe(false)
  })
})

describe('security-key views', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    stubWebAuthn()
  })
  afterEach(() => vi.unstubAllGlobals())

  it('enrolment offers a security key next to the app and shows the recovery codes once', async () => {
    useSession().apply({ user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: [], mfa_setup_required: true })
    await router.push('/security/enrol')
    const fetch = stubFetch((url) => {
      if (url.endsWith('/me/mfa/enroll')) return { status: 200, body: { secret: 'JBSWY3DPEHPK3PXP', otpauth_uri: 'otpauth://totp/Tangra:a@x.test?secret=JBSWY3DPEHPK3PXP' } }
      if (url.endsWith('/webauthn/register/options')) return { status: 200, body: creation }
      if (url.endsWith('/webauthn/register')) return { status: 201, body: { key: { id: 'k1', name: 'YubiKey' }, recovery_codes: ['AAAAA-BBBBB'] } }
      return { status: 200, body: { user: { id: 'u1', email: 'a@x.test', mfa_enabled: true }, tenant: { id: 't1' }, roles: [] } }
    })
    const w = mountView(MfaEnrol)
    await flushPromises()
    await vi.waitFor(() => expect(w.find('[data-test="qr"]').exists()).toBe(true))
    await w.find('[data-test="key-name"] input').setValue('YubiKey')
    await w.find('[data-test="add-key"]').trigger('click')
    await flushPromises()
    expect(body(fetch.mock.calls.find((c) => String(c[0]).endsWith('/register/options')))).toEqual({ name: 'YubiKey' })
    expect(create).toHaveBeenCalledOnce()
    expect(body(fetch.mock.calls.find((c) => String(c[0]).endsWith('/webauthn/register'))).credential.rawId).toBe('CAkK')
    expect(w.findAll('[data-test="recovery-codes"] li').map((l) => l.text())).toEqual(['AAAAA-BBBBB'])
    expect(w.find('[data-test="add-key"]').exists()).toBe(false)
    w.unmount()
  })

  it('enrolment reports a cancelled key prompt and stores nothing', async () => {
    useSession().apply({ user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: [] })
    const fetch = stubFetch((url) => (url.endsWith('/register/options') ? { status: 200, body: creation } : { status: 200, body: { secret: 'S', otpauth_uri: 'otpauth://totp/x' } }))
    create.mockRejectedValueOnce(new DOMException('cancel', 'NotAllowedError'))
    const w = mountView(MfaEnrol)
    await flushPromises()
    await w.find('[data-test="key-name"] input').setValue('Desk')
    await w.find('[data-test="add-key"]').trigger('click')
    await flushPromises()
    expect(w.find('[data-test="key-error"]').text()).toMatch(/cancelled or timed out/)
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/webauthn/register'))).toBe(false)
    w.unmount()
  })

  it('challenge offers the key first, signs in with it, and switches to a code', async () => {
    const signin = useSignin()
    signin.challenge = 'ch-1'
    signin.methods = ['webauthn', 'totp', 'recovery']
    signin.next = '/sessions'
    const fetch = stubFetch((url) => {
      if (url.endsWith('/signin/mfa/webauthn/options')) return { status: 200, body: request }
      if (url.endsWith('/signin/mfa/webauthn')) return { status: 200, body: { signed_in: true } }
      if (url.endsWith('/api/v1/session')) return { status: 200, body: { user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: [] } }
      return { status: 404, body: {} }
    })
    const w = mountView(MfaChallenge)
    await flushPromises()
    expect(w.find('[data-test="use-key"]').exists()).toBe(true)
    expect(w.find('[data-test="code"]').exists()).toBe(false)
    await w.find('[data-test="use-key"]').trigger('click')
    await flushPromises()
    expect(body(fetch.mock.calls.find((c) => String(c[0]).endsWith('/webauthn/options')))).toEqual({ challenge: 'ch-1' })
    expect(get).toHaveBeenCalledOnce()
    const done = body(fetch.mock.calls.find((c) => String(c[0]).endsWith('/signin/mfa/webauthn')))
    expect(done.challenge).toBe('ch-1')
    expect(done.credential.response.signature).toBe('BA')
    await vi.waitFor(() => expect(router.currentRoute.value.path).toBe('/sessions'))
    w.unmount()
    // Switching to a code shows the code form; a refused key names the reason.
    signin.challenge = 'ch-2'
    signin.methods = ['webauthn', 'recovery']
    stubFetch((url) => (url.endsWith('/options') ? { status: 200, body: request } : { status: 401, body: { reason: 'key_flagged' } }))
    const m = mountView(MfaChallenge)
    await flushPromises()
    await m.find('[data-test="use-key"]').trigger('click')
    await flushPromises()
    expect(m.find('[data-test="error"]').text()).toMatch(/possibly cloned/)
    await m.find('[data-test="use-code"]').trigger('click')
    await flushPromises()
    expect(m.find('[data-test="code"]').exists()).toBe(true)
    expect(m.text()).toMatch(/recovery code/)
    m.unmount()
  })

  it('challenge without key support or key method keeps the code form only', async () => {
    vi.unstubAllGlobals()
    const signin = useSignin()
    signin.challenge = 'ch-3'
    signin.methods = ['webauthn', 'recovery']
    stubFetch(() => ({ status: 404, body: {} }))
    const w = mountView(MfaChallenge)
    await flushPromises()
    expect(w.find('[data-test="use-key"]').exists()).toBe(false)
    expect(w.find('[data-test="code"]').exists()).toBe(true)
    expect(w.find('[data-test="key-unsupported"]').text()).toMatch(/does not support security keys/)
    w.unmount()
  })

  it('lists keys, renames one and removes one after confirming with a code or a key', async () => {
    const keys = [
      { id: 'k1', name: 'Desk', created_at: '2026-09-01T10:00:00Z', last_used_at: '2026-09-20T08:00:00Z', flagged: false },
      { id: 'k2', name: 'Old', created_at: '2026-08-01T10:00:00Z', last_used_at: null, flagged: true },
    ]
    const fetch = stubFetch((url, init) => {
      if (url.endsWith('/stepup/options')) return { status: 200, body: request }
      if (init?.method === 'PATCH') return { status: 200, body: { key: { ...keys[0], name: 'Office' } } }
      if (init?.method === 'DELETE') return { status: 204, body: null }
      return { status: 404, body: {} }
    })
    const w = mountView(SecurityKeys, { keys, rpId: 'localhost', totp: true })
    await flushPromises()
    const rows = w.findAll('[data-test="key-row"]')
    expect(rows.length).toBe(2)
    expect(rows[0]!.text()).toContain('Desk')
    expect(rows[0]!.find('time').exists()).toBe(true)
    expect(rows[1]!.text()).toMatch(/Never used/)
    expect(rows[1]!.find('[data-test="key-flagged"]').exists()).toBe(true)
    // Rename.
    await rows[0]!.find('[data-test="rename"]').trigger('click')
    await flushPromises()
    const input = document.querySelector('[data-test="rename-name"] input') as HTMLInputElement
    input.value = 'Office'
    input.dispatchEvent(new Event('input'))
    ;(document.querySelector('[data-test="rename-save"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(body(fetch.mock.calls.find((c) => (c[1] as RequestInit).method === 'PATCH'))).toEqual({ name: 'Office' })
    expect(fetch.mock.calls.find((c) => (c[1] as RequestInit).method === 'PATCH')![0]).toBe('/api/v1/me/mfa/webauthn/k1')
    // Remove with a code.
    await w.findAll('[data-test="remove"]')[1]!.trigger('click')
    await flushPromises()
    const code = document.querySelector('[data-test="remove-code"] input') as HTMLInputElement
    code.value = 'ABCDE-FGHJK'
    code.dispatchEvent(new Event('input'))
    ;(document.querySelector('[data-test="remove-with-code"]') as HTMLButtonElement).click()
    await flushPromises()
    const del = fetch.mock.calls.find((c) => (c[1] as RequestInit).method === 'DELETE')
    expect(del![0]).toBe('/api/v1/me/mfa/webauthn/k2')
    expect(body(del)).toEqual({ code: 'ABCDE-FGHJK' })
    expect(w.findComponent(SecurityKeys).emitted('changed')).toBeTruthy()
    // Remove with a key assertion (step-up).
    await w.findAll('[data-test="remove"]')[0]!.trigger('click')
    await flushPromises()
    ;(document.querySelector('[data-test="remove-with-key"]') as HTMLButtonElement).click()
    await flushPromises()
    const del2 = fetch.mock.calls.filter((c) => (c[1] as RequestInit).method === 'DELETE').at(-1)
    expect(del2![0]).toBe('/api/v1/me/mfa/webauthn/k1')
    expect(body(del2).credential.response.authenticatorData).toBe('Aw')
    w.unmount()
  })

  it('account shows the authenticator app and security keys together as second factors', async () => {
    useSession().apply({ user: { id: 'u1', email: 'a@x.test', mfa_enabled: true }, tenant: { id: 't1' }, roles: [] })
    await router.push('/security')
    let keys: unknown[] = []
    const fetch = stubFetch((url) => {
      if (url.endsWith('/api/v1/me/mfa')) return { status: 200, body: { totp: false, keys, recovery_codes_left: keys.length ? 10 : 0, required: false, webauthn: { enabled: true, rp_id: 'localhost' } } }
      if (url.endsWith('/webauthn/register/options')) return { status: 200, body: creation }
      if (url.endsWith('/webauthn/register')) {
        keys = [{ id: 'k1', name: 'Desk', created_at: '2026-09-01T10:00:00Z', last_used_at: null, flagged: false }]
        return { status: 201, body: { key: keys[0], recovery_codes: ['AAAAA-BBBBB'] } }
      }
      if (url.endsWith('/api/v1/session')) return { status: 200, body: { user: { id: 'u1', email: 'a@x.test', mfa_enabled: true }, tenant: { id: 't1' }, roles: [] } }
      return { status: 404, body: {} }
    })
    const w = mountView(Account)
    await flushPromises()
    const card = w.find('[data-test="mfa-card"]')
    expect(card.text()).toContain('Second factors')
    // mfa_enabled comes from a key here: the app is not claimed as set up.
    expect(card.find('[data-test="enrol"]').exists()).toBe(true)
    expect(card.find('[data-test="no-keys"]').exists()).toBe(true)
    await card.find('[data-test="key-name"] input').setValue('Desk')
    await card.find('[data-test="add-key"]').trigger('click')
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/webauthn/register'))).toBe(true)
    expect(w.findAll('[data-test="recovery-codes"] li').map((l) => l.text())).toEqual(['AAAAA-BBBBB'])
    await w.find('[data-test="codes-dismiss"]').trigger('click')
    await flushPromises()
    expect(w.findAll('[data-test="key-row"]').length).toBe(1)
    expect(w.find('[data-test="codes-left"]').text()).toContain('10')
    w.unmount()
  })

  it('names why a removal was refused', async () => {
    stubFetch(() => ({ status: 409, body: { reason: 'last_factor_required' } }))
    const w = mountView(SecurityKeys, { keys: [{ id: 'k1', name: 'Only', created_at: '2026-09-01T10:00:00Z', last_used_at: null, flagged: false }], rpId: 'localhost', totp: false })
    await w.find('[data-test="remove"]').trigger('click')
    await flushPromises()
    ;(document.querySelector('[data-test="remove-with-key"]') as HTMLButtonElement).click()
    await flushPromises()
    expect(document.querySelector('[data-test="remove-error"]')!.textContent).toMatch(/requires a second factor/)
    w.unmount()
  })

  it('admin user page shows the second factors and resets them after confirmation', async () => {
    const users = [{ id: 'u2', email: 'bob@x.test', display_name: 'Bob', status: 'active', mfa_enabled: true, roles: ['member'], last_signin_at: null }]
    let reset = false
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/admin/users/u2/mfa/reset') {
        reset = true
        return { status: 204, body: null }
      }
      if (url === '/api/v1/admin/users/u2/mfa')
        return { status: 200, body: reset ? { totp: false, keys: [], recovery_codes_left: 0 } : { totp: true, keys: [{ name: 'Bob desk', created_at: '2026-09-01T10:00:00Z', last_used_at: null, flagged: false }], recovery_codes_left: 8 } }
      if (url === '/api/v1/admin/roles') return { status: 200, body: [] }
      if (url.startsWith('/api/v1/admin/users') && init?.method === 'GET') return { status: 200, body: { items: users } }
      return { status: 200, body: { items: [] } }
    })
    useSession().apply({ user: { id: 'u1', email: 'alice@x.test' }, tenant: { id: 't1', slug: 'acme' }, roles: ['owner'] })
    await router.push('/admin/users/u2')
    const w = mountView(UserDetail)
    await flushPromises()
    const sec = w.find('[data-test="user-mfa"]')
    expect(sec.text()).toContain('Authenticator app')
    expect(sec.text()).toContain('Bob desk')
    expect(sec.text()).toContain('8')
    await w.find('[data-test="mfa-reset"]').trigger('click')
    await flushPromises()
    ;[...document.querySelectorAll('[role=dialog] button')].find((b) => b.textContent?.trim() === 'Reset second factors')!.dispatchEvent(new MouseEvent('click', { bubbles: true }))
    await flushPromises()
    expect(fetch.mock.calls.some((c) => c[0] === '/api/v1/admin/users/u2/mfa/reset' && (c[1] as RequestInit).method === 'POST')).toBe(true)
    await flushPromises()
    expect(w.find('[data-test="user-mfa"]').text()).toMatch(/No second factor/)
    w.unmount()
  })
})
