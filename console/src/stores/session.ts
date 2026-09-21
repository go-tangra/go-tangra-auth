import { defineStore } from 'pinia'
import { api, ApiError, onApiEvent } from '@/api/client'
import type { components } from '@/api/schema'

export type User = components['schemas']['User']
export type TenantRef = components['schemas']['TenantRef']

/** Shape of GET /api/v1/session. */
export interface SessionInfo {
  session_id?: string
  user: User
  tenant: TenantRef
  roles?: string[]
  operator?: boolean
  mfa_setup_required?: boolean
}

export type SessionStatus = 'unknown' | 'anonymous' | 'authenticated' | 'outage'

/** DOM event the platform shell listens for after a profile change (feature 004). */
export const SESSION_CHANGED_EVENT = 'freya:session-changed'

/** Tells the shell (when hosted) that the signed-in person's profile changed. */
export function announceSessionChanged(): void {
  window.dispatchEvent(new CustomEvent(SESSION_CHANGED_EVENT))
}

export const useSession = defineStore('session', {
  state: () => ({
    status: 'unknown' as SessionStatus,
    user: null as User | null,
    tenant: null as TenantRef | null,
    roles: [] as string[],
    operator: false,
    sessionId: '' as string,
    mfaSetupRequired: false,
    pending: null as Promise<void> | null,
  }),
  getters: {
    signedIn: (s) => s.status === 'authenticated',
    hasRole: (s) => (role: string) => s.roles.includes(role),
    hasAnyRole: (s) => (roles: string[]) => roles.some((r) => s.roles.includes(r)),
    isAdmin: (s) => s.roles.includes('owner') || s.roles.includes('admin'),
  },
  actions: {
    /** Loads the current session once; concurrent callers share the request. */
    load(force = false): Promise<void> {
      if (this.pending && !force) return this.pending
      this.pending = (async () => {
        try {
          this.apply(await api<SessionInfo>('GET', '/api/v1/session'))
        } catch (err) {
          if (err instanceof ApiError && err.status === 401) this.reset('anonymous')
          else if (err instanceof ApiError && (err.status === 0 || err.status >= 500)) this.status = 'outage'
          else throw err
        } finally {
          this.pending = null
        }
      })()
      return this.pending
    },
    apply(info: SessionInfo): void {
      this.user = info.user
      this.tenant = info.tenant
      this.roles = info.roles ?? []
      this.operator = info.operator ?? false
      this.sessionId = info.session_id ?? ''
      this.mfaSetupRequired = info.mfa_setup_required ?? false
      this.status = 'authenticated'
    },
    reset(status: SessionStatus = 'anonymous'): void {
      this.user = null
      this.tenant = null
      this.roles = []
      this.operator = false
      this.sessionId = ''
      this.mfaSetupRequired = false
      this.status = status
    },
    async signOut(): Promise<void> {
      try {
        await api('POST', '/api/v1/signout')
      } catch (err) {
        if (!(err instanceof ApiError)) throw err
      } finally {
        this.reset()
      }
    },
    /** Keeps the store in step with transport events (session loss, outage). */
    bindEvents(): () => void {
      return onApiEvent((ev) => {
        if (ev === 'unauthenticated' && this.status === 'authenticated') this.reset()
        if (ev === 'outage') this.status = 'outage'
        if (ev === 'recovered' && this.status === 'outage') this.status = 'unknown'
      })
    },
  },
})
