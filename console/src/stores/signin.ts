import { defineStore } from 'pinia'
import { ApiError } from '@/api/client'
import { useSession } from '@/stores/session'
import { leaveTo } from '@/base'

/** Body of POST /api/v1/signin and /api/v1/signin/mfa. */
export interface SignInResponse {
  signed_in?: boolean
  mfa_required?: boolean
  challenge?: string
  session_id?: string
  roles?: string[]
  mfa_setup_required?: boolean
}

/** Only same-origin paths are honoured as return targets. */
export function safeNext(raw: unknown): string {
  const s = typeof raw === 'string' ? raw : ''
  if (!s.startsWith('/') || s.startsWith('//') || s.includes('\\')) return '/'
  // Never send a freshly signed-in person back to a sign-in page: a `next`
  // that targets sign-in (e.g. a nested /console/signin?next=… captured while
  // looping) would bounce them straight back out. Compare the path only.
  const path = s.split(/[?#]/, 1)[0] ?? ''
  if (path === '/signin' || path === '/console/signin' || path.endsWith('/signin')) return '/'
  return s
}

// The MFA challenge lives here (memory only) between the two sign-in steps so
// it never appears in the URL or in storage.
export const useSignin = defineStore('signin', {
  state: () => ({ challenge: '' as string, next: '/' as string }),
  actions: {
    /** Human-readable, cause-agnostic message for a sign-in failure. */
    messageFor(err: unknown): string {
      if (err instanceof ApiError) {
        if (err.status === 423) return 'This account is temporarily locked. Try again later.'
        if (err.status === 429) return 'Too many attempts. Please wait a moment and try again.'
        if (err.status === 401 || err.status === 400) return 'Sign-in failed. Check your organisation, email and password.'
      }
      return 'Sign-in is not available right now. Please try again.'
    },
    /**
     * Completes a sign-in: reloads the session and returns to `next` through
     * the router of the hosting application (standalone or platform shell).
     */
    async finish(res: SignInResponse, navigate: (to: string) => Promise<unknown>): Promise<void> {
      const session = useSession()
      await session.load(true)
      const target = res.mfa_setup_required ? '/console/security/enrol' : this.next
      this.challenge = ''
      this.next = '/'
      await leaveTo(navigate, target)
    },
  },
})
