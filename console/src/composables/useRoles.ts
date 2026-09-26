import { ref } from 'vue'
import { api, ApiError } from '@/api/client'
import type { components } from '@/api/schema'

export type RoleOrigin = 'builtin' | 'module' | 'custom'
/**
 * A role as GET /admin/roles returns it. The feature-019 fields (origin,
 * module, retired …) are declared locally until the generated schema catches up.
 */
export type Role = components['schemas']['Role'] & {
  description?: string
  origin?: RoleOrigin
  module?: string
  module_display_name?: string
  module_slug?: string
  locked?: boolean
  retired?: boolean
  retired_at?: string | null
}

/** The role's origin; servers predating modules only send `builtin`. */
export const roleOrigin = (r: Role): RoleOrigin => r.origin ?? (r.builtin ? 'builtin' : 'custom')
/** Built-in and module roles cannot be edited or removed (clone them instead). */
export const roleLocked = (r: Role): boolean => r.locked ?? roleOrigin(r) !== 'custom'
/** Every role except owner can be cloned. */
export const roleClonable = (r: Role): boolean => r.slug !== 'owner'
/** Picker label: module roles name their module ("Warden viewer · Warden"). */
export function roleLabel(r: Role): string {
  const name = r.display_name || r.slug || ''
  return roleOrigin(r) === 'module' && r.module_display_name ? `${name} · ${r.module_display_name}` : name
}
/** A retired role may stay on a target that already holds it but is never newly assigned. */
export const roleAssignable = (r: Role, held: readonly string[]): boolean => !r.retired || held.includes(r.id ?? '')

/** Loads the tenant's roles once; tolerates the endpoint being unavailable. */
export function useRoles() {
  const roles = ref<Role[]>([])
  const loaded = ref(false)
  async function load(): Promise<void> {
    try {
      roles.value = await api<Role[]>('GET', '/api/v1/admin/roles')
    } catch (err) {
      if (!(err instanceof ApiError)) throw err
      roles.value = []
    } finally {
      loaded.value = true
    }
  }
  return { roles, loaded, load }
}
