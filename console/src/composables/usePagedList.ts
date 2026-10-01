import { ref, watch, type Ref } from 'vue'
import { useListQuery, type ListQuery, type ListQueryOptions } from '@go-tangra/ui'
import { api } from '@/api/client'

// Server-paged tables (go-tangra specs/032-server-side-tables): every console
// table asks the server for one page (page, page_size, sort, order) and shows
// the total, which counts only what the caller may see; sorting orders the
// whole list on the server. The table state lives in the URL under a
// per-table prefix (?users.page=…).

/** A list-contract page. */
export interface Page<T> {
  items: T[]
  total: number
  page: number
  page_size: number
  sort: string
  order: 'asc' | 'desc'
}

export const PAGE_SIZE = 25
/** The largest page the server answers: option lists (pickers). */
export const OPTIONS_SIZE = 200

/** The kit list-query options of a table with these server sort fields. */
export function listOptions(sortable: readonly string[], key: string, dir: 'asc' | 'desc' = 'asc', size = PAGE_SIZE): ListQueryOptions {
  return { sortable: [...sortable], defaultSort: { key, dir }, defaultSize: size }
}

// The sort fields each console list accepts (api/openapi/console.yaml,
// internal/store/lists.go).
export const USER_LIST = listOptions(['email', 'display_name', 'status', 'last_signin_at', 'created_at'], 'email')
export const AUDIT_LIST = listOptions(['ts'], 'ts', 'desc', 50)
export const GROUP_LIST = listOptions(['name', 'member_count', 'created_at'], 'name')
export const MEMBER_LIST = listOptions(['added_at', 'email', 'display_name', 'status'], 'added_at', 'desc')
export const ROLE_LIST = listOptions(['display_name', 'slug', 'origin'], 'display_name')
export const CLIENT_LIST = listOptions(['display_name', 'client_id'], 'display_name')
export const TENANT_LIST = listOptions(['display_name', 'slug', 'status', 'kind', 'created_at'], 'display_name')
export const SESSION_LIST = listOptions(['created_at', 'last_seen_at', 'expires_at'], 'created_at', 'desc')
export const DIRECTORY_LIST = listOptions(['name', 'created_at'], 'name')

/** Blank filter values are not sent. */
function compact(f: Record<string, unknown>): Record<string, string | number> {
  const out: Record<string, string | number> = {}
  for (const [k, v] of Object.entries(f)) if (v !== undefined && v !== null && v !== '') out[k] = v as string | number
  return out
}

export interface PagedList<T> {
  lq: ListQuery
  items: Ref<T[]>
  total: Ref<number>
  loading: Ref<boolean>
  /** Loads the current page; resolves false when it failed (onError ran) or was superseded. */
  load(): Promise<boolean>
  /** Filters changed: back to page 1 (which loads) or reload when already there. */
  refilter(): Promise<void>
}

/**
 * One server-paged table bound to the URL (key) and the list at path. filter
 * returns the current filter parameters; onError receives a failed load
 * (superseded responses are dropped silently).
 */
export function usePagedList<T>(key: string, path: string | (() => string), opts: ListQueryOptions,
  filter: () => Record<string, unknown> = () => ({}), onError: (err: unknown) => void = () => {}): PagedList<T> {
  const lq = useListQuery(key, opts)
  const items = ref<T[]>([]) as Ref<T[]>
  const total = ref(0)
  const loading = ref(false)
  async function load(): Promise<boolean> {
    loading.value = true
    try {
      const url = typeof path === 'function' ? path() : path
      const res = await lq.track(api<Page<T>>('GET', url, undefined, { query: { ...compact(filter()), ...lq.query.value } }))
      if (!res) return false
      items.value = res.items ?? []
      total.value = res.total ?? 0
      lq.clampTo(res.page)
      return true
    } catch (err) {
      onError(err)
      return false
    } finally {
      loading.value = false
    }
  }
  async function refilter(): Promise<void> {
    if (lq.page.value !== 1) lq.resetPage()
    else await load()
  }
  watch(lq.query, () => void load())
  return { lq, items, total, loading, load, refilter }
}
