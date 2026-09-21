import { ref } from 'vue'
import { api, ApiError } from '@/api/client'
import type { components } from '@/api/schema'

export type Role = components['schemas']['Role']

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
