// The console's transport: the kit client (same-origin, CSRF double submit,
// closed reason vocabulary) plus the outage / session-loss events the session
// store and the outage page listen to.
import { createApi, ApiError, csrfToken, CSRF_COOKIE, CSRF_HEADER, type Api, type Method, type RequestOptions } from '@freya/ui/api'
import { registerReasons } from '@freya/ui/forms'
import type { paths } from './schema'

export { ApiError, csrfToken, CSRF_COOKIE, CSRF_HEADER }
export type { Method, RequestOptions }

// Path names are checked against the OpenAPI contract at compile time.
export type ApiPath = keyof paths

// Wording for the console's own closed-vocabulary reasons (api/openapi/console.yaml).
registerReasons({
  last_owner: 'The last owner of an organisation cannot be removed or demoted.',
  self_escalation: 'You can only grant permissions you hold yourself.',
  not_found: 'That record does not exist in your organisation.',
  validation_failed: 'Please check the values you entered.',
  password_policy: 'The password does not meet the organisation policy.',
  invalid_token: 'This invitation link is invalid or has expired.',
  invalid_code: 'That code was not accepted. Codes change every 30 seconds.',
  mfa_required: 'Your organisation requires a second factor.',
  name_taken: 'A group with that name already exists.',
  member_count_mismatch: 'The group changed while you were looking at it. Reload and try again.',
  owner_via_group: 'The owner role can only be assigned to people directly.',
  unsupported_type: 'Use a PNG, JPEG or WebP picture.',
  too_large_dimensions: 'The picture is too large; use one under 4096 × 4096 pixels.',
  not_an_image: 'That file could not be read as a picture.',
  decode_failed: 'That file could not be read as a picture.',
  body_too_large: 'The file is too large (2 MB at most).',
  unavailable: 'The service is temporarily unavailable.',
})

export type ApiEvent = 'outage' | 'unauthenticated' | 'recovered'
type Listener = (event: ApiEvent) => void
const listeners = new Set<Listener>()

/** Subscribe to transport-level events (outage, session loss). */
export function onApiEvent(listener: Listener): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

function emit(event: ApiEvent): void {
  for (const l of listeners) l(event)
}

/** Maps a refused call onto the console's events; 5xx becomes `unavailable`. */
function classify(err: unknown): never {
  if (err instanceof ApiError) {
    if (err.status === 0 || err.status >= 500) {
      emit('outage')
      throw err.status >= 500 ? new ApiError(err.status, 'unavailable') : err
    }
    emit('recovered')
    if (err.status === 401) emit('unauthenticated')
  }
  throw err
}

// Every console path is absolute ("/api/v1/…"), so the base only names the module.
const transport = createApi({ base: '/api/v1' })

/** Calls the auth API. Non-2xx responses reject with ApiError carrying the server's `reason`. */
export const api: Api = (async <T = unknown,>(method: Method, path: ApiPath | string, body?: unknown, opts: RequestOptions = {}): Promise<T> => {
  try {
    const out = await transport<T>(method, path, body, opts)
    emit('recovered')
    return out
  } catch (err) {
    return classify(err)
  }
}) as Api
Object.defineProperty(api, 'base', { value: transport.base })
api.upload = transport.upload
api.fileUrl = transport.fileUrl

/**
 * Uploads raw bytes (an avatar) with PUT. Same error mapping as api(); the
 * browser sends the file's own content type and the CSRF header.
 */
export async function upload<T = unknown>(path: string, file: Blob): Promise<T> {
  let res: Response
  try {
    res = await fetch(path, {
      method: 'PUT',
      headers: { Accept: 'application/json', 'Content-Type': file.type || 'application/octet-stream', [CSRF_HEADER]: csrfToken() },
      credentials: 'same-origin',
      body: file,
    })
  } catch {
    emit('outage')
    throw new ApiError(0, 'network')
  }
  if (res.status >= 500) {
    emit('outage')
    throw new ApiError(res.status, 'unavailable')
  }
  emit('recovered')
  if (res.status === 204) return undefined as T
  const data: unknown = await res.json().catch(() => ({}))
  if (!res.ok) {
    const reason = typeof data === 'object' && data !== null && 'reason' in data ? String((data as { reason: unknown }).reason) : 'error'
    if (res.status === 401) emit('unauthenticated')
    throw new ApiError(res.status, reason)
  }
  return data as T
}
