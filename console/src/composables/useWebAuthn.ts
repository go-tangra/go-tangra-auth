// Security keys (feature 018): the browser side of the WebAuthn ceremonies.
// The server sends options as JSON ({"publicKey": …}, base64url fields) and
// takes back PublicKeyCredential.toJSON(). Browsers with the Level 3 JSON
// helpers use them; older ones get the same conversion by hand.
import { ref } from 'vue'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import type { SignInResponse } from '@/stores/signin'

export type OptionsJSON = { publicKey: Record<string, unknown> }
export type CredentialJSON = Record<string, unknown>

/** A registered key as its owner sees it (never key material). */
export interface KeyView {
  id: string
  name: string
  created_at: string
  last_used_at: string | null
  flagged: boolean
}

/** GET /api/v1/me/mfa. */
export interface MfaState {
  totp: boolean
  keys: KeyView[]
  recovery_codes_left: number
  required: boolean
  webauthn?: { enabled: boolean; rp_id: string }
}

export function b64urlEncode(buf: ArrayBuffer | ArrayBufferView): string {
  const bytes = buf instanceof ArrayBuffer ? new Uint8Array(buf) : new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  let s = ''
  for (const b of bytes) s += String.fromCharCode(b)
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export function b64urlDecode(s: string): ArrayBuffer {
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + '==='.slice((s.length + 3) % 4)
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out.buffer
}

type PKCStatic = {
  parseCreationOptionsFromJSON?: (o: unknown) => PublicKeyCredentialCreationOptions
  parseRequestOptionsFromJSON?: (o: unknown) => PublicKeyCredentialRequestOptions
}
const pkc = (): PKCStatic | undefined => (globalThis as unknown as { PublicKeyCredential?: PKCStatic }).PublicKeyCredential

/** Whether this browser can use security keys at all. */
export function webAuthnSupported(): boolean {
  return pkc() !== undefined && typeof navigator !== 'undefined' && typeof navigator.credentials?.create === 'function'
}

/** Keys are bound to the relying party: the page host must be it or below it. */
export function hostMatches(rpId: string, host: string = window.location.hostname): boolean {
  return host === rpId || (host.endsWith('.' + rpId) && rpId.includes('.'))
}

type DescriptorJSON = { id: string; type: string; transports?: string[] }
const descriptors = (list: unknown) =>
  ((list as DescriptorJSON[] | undefined) ?? []).map((d) => ({ ...d, id: b64urlDecode(d.id) }) as PublicKeyCredentialDescriptor)

/** Server creation options → navigator.credentials.create() argument. */
export function creationOptions(json: OptionsJSON): CredentialCreationOptions {
  const P = pkc()
  if (P?.parseCreationOptionsFromJSON) return { publicKey: P.parseCreationOptionsFromJSON(json.publicKey) }
  const o = json.publicKey as Record<string, unknown> & { user: Record<string, unknown> }
  return {
    publicKey: {
      ...(o as unknown as PublicKeyCredentialCreationOptions),
      challenge: b64urlDecode(o.challenge as string),
      user: { ...(o.user as unknown as PublicKeyCredentialUserEntity), id: b64urlDecode(o.user.id as string) },
      excludeCredentials: descriptors(o.excludeCredentials),
    },
  }
}

/** Server request options → navigator.credentials.get() argument. */
export function requestOptions(json: OptionsJSON): CredentialRequestOptions {
  const P = pkc()
  if (P?.parseRequestOptionsFromJSON) return { publicKey: P.parseRequestOptionsFromJSON(json.publicKey) }
  const o = json.publicKey
  return { publicKey: { ...(o as unknown as PublicKeyCredentialRequestOptions), challenge: b64urlDecode(o.challenge as string), allowCredentials: descriptors(o.allowCredentials) } }
}

type RawResponse = {
  clientDataJSON: ArrayBuffer
  attestationObject?: ArrayBuffer
  getTransports?: () => string[]
  authenticatorData?: ArrayBuffer
  signature?: ArrayBuffer
  userHandle?: ArrayBuffer | null
}

/** PublicKeyCredential → the JSON the server parses (toJSON() when available). */
export function credentialJSON(cred: PublicKeyCredential): CredentialJSON {
  const native = (cred as unknown as { toJSON?: () => CredentialJSON }).toJSON
  if (typeof native === 'function') return native.call(cred)
  const r = cred.response as unknown as RawResponse
  const response: Record<string, unknown> = { clientDataJSON: b64urlEncode(r.clientDataJSON) }
  if (r.attestationObject) {
    response.attestationObject = b64urlEncode(r.attestationObject)
    response.transports = r.getTransports?.() ?? []
  }
  if (r.authenticatorData) response.authenticatorData = b64urlEncode(r.authenticatorData)
  if (r.signature) response.signature = b64urlEncode(r.signature)
  if (r.userHandle) response.userHandle = b64urlEncode(r.userHandle)
  return {
    id: cred.id,
    rawId: b64urlEncode(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? null,
    clientExtensionResults: cred.getClientExtensionResults(),
    response,
  }
}

const reasons: Record<string, string> = {
  mfa_failed: 'The security key was not accepted.',
  key_flagged: 'This security key is flagged as possibly cloned and can no longer be used. Sign in another way and remove it.',
  invalid_challenge: 'The sign-in has expired. Start again.',
  registration_failed: 'The security key could not be registered. Try again.',
  already_registered: 'This security key is already registered.',
  name_taken: 'You already have a security key with that name.',
  key_limit: 'You can register at most 10 security keys.',
  invalid_name: 'Enter a name of 1 to 64 characters.',
  webauthn_disabled: 'Security keys are not enabled on this platform.',
  confirmation_failed: 'The confirmation was not accepted.',
  last_factor_required: 'Your organisation requires a second factor; add another one before removing this key.',
  no_keys: 'You have no security key that can confirm this.',
}

/** Human-readable message for a browser or API refusal. */
export function webAuthnMessage(err: unknown, rpId = ''): string {
  if (err instanceof ApiError) {
    if (err.status === 423) return 'This account is temporarily locked. Try again later.'
    if (err.status === 429) return 'Too many attempts. Please wait a moment and try again.'
    return reasons[err.reason] ?? reasonMessage(err.reason)
  }
  if (err instanceof DOMException) {
    switch (err.name) {
      case 'NotAllowedError':
      case 'AbortError':
        return 'The security key prompt was cancelled or timed out.'
      case 'InvalidStateError':
        return 'This security key is already registered.'
      case 'SecurityError':
        return `Security keys only work at ${rpId || 'the platform address'}. Open the console there and try again.`
      case 'NotSupportedError':
        return 'This browser or key does not support the required security key features.'
    }
  }
  if (err instanceof Error && err.message.startsWith('webauthn:')) return err.message.slice('webauthn:'.length)
  return 'The security key could not be used. Try again.'
}

function relyingParty(json: OptionsJSON): string {
  const p = json.publicKey as { rp?: { id?: string }; rpId?: string }
  return p.rp?.id ?? p.rpId ?? ''
}

function guard(json: OptionsJSON): void {
  if (!webAuthnSupported()) throw new Error('webauthn:This browser does not support security keys. Use another method.')
  const rp = relyingParty(json)
  if (rp && !hostMatches(rp)) throw new Error(`webauthn:Security keys only work at ${rp}. Open the console there and try again.`)
}

/** Runs navigator.credentials.create() for server options. */
export async function createCredential(json: OptionsJSON): Promise<CredentialJSON> {
  guard(json)
  const cred = (await navigator.credentials.create(creationOptions(json))) as PublicKeyCredential | null
  if (!cred) throw new DOMException('no credential', 'NotAllowedError')
  return credentialJSON(cred)
}

/** Runs navigator.credentials.get() for server options. */
export async function getCredential(json: OptionsJSON): Promise<CredentialJSON> {
  guard(json)
  const cred = (await navigator.credentials.get(requestOptions(json))) as PublicKeyCredential | null
  if (!cred) throw new DOMException('no credential', 'NotAllowedError')
  return credentialJSON(cred)
}

/** Registration, sign-in and step-up with a security key; errors land in `error`. */
export function useWebAuthn() {
  const supported = webAuthnSupported()
  const busy = ref(false)
  const error = ref<string | null>(null)

  async function run<T>(fn: () => Promise<T>): Promise<T | null> {
    busy.value = true
    error.value = null
    let rp = ''
    try {
      return await fn()
    } catch (err) {
      if (err instanceof DOMException && err.name === 'SecurityError') rp = window.location.hostname
      error.value = webAuthnMessage(err, rp)
      return null
    } finally {
      busy.value = false
    }
  }

  /** Adds a named key; recovery codes come back for the first factor only. */
  const register = (name: string) =>
    run(async () => {
      const opts = await api<OptionsJSON>('POST', '/api/v1/me/mfa/webauthn/register/options', { name })
      const credential = await createCredential(opts)
      return api<{ key: KeyView; recovery_codes?: string[] }>('POST', '/api/v1/me/mfa/webauthn/register', { credential })
    })

  /** Completes the second sign-in step with a key. */
  const signIn = (challenge: string) =>
    run(async () => {
      const opts = await api<OptionsJSON>('POST', '/api/v1/signin/mfa/webauthn/options', { challenge })
      const credential = await getCredential(opts)
      return api<SignInResponse>('POST', '/api/v1/signin/mfa/webauthn', { challenge, credential })
    })

  /** An assertion that confirms a removal. */
  const stepUp = () =>
    run(async () => {
      const opts = await api<OptionsJSON>('POST', '/api/v1/me/mfa/stepup/options')
      return getCredential(opts)
    })

  return { supported, busy, error, register, signIn, stepUp }
}
