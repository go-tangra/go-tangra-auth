import type { RouteRecordRaw } from 'vue-router'
import { routes as consoleRoutes } from '@/router/routes'

// The console as a federated remote: the same route records, mounted by the
// platform shell under /console. The catch-all stays scoped to the prefix so
// it never shadows other modules.
const prefix = '/console'

// Route names stay as declared so named navigation inside the console keeps
// working; only names the shell reserves for itself are prefixed.
const reserved = new Set(['home', 'forbidden', 'notfound', 'outage', 'ops', 'ops-allowlist', 'ops-audit'])

function mount(r: RouteRecordRaw): RouteRecordRaw {
  const path = r.path === '/:pathMatch(.*)*' ? prefix + '/:pathMatch(.*)*' : prefix + (r.path === '/' ? '' : r.path)
  const name = r.name && reserved.has(String(r.name)) ? `auth:${String(r.name)}` : r.name
  return { ...r, path, name, meta: { ...(r.meta ?? {}), module: 'auth' } } as RouteRecordRaw
}

export const routes: RouteRecordRaw[] = consoleRoutes.map(mount)
export default routes
