import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import type { Component } from 'vue'
import Users from '@/views/admin/Users.vue'
import Groups from '@/views/admin/Groups.vue'
import GroupDetail from '@/views/admin/GroupDetail.vue'
import Roles from '@/views/admin/Roles.vue'
import Clients from '@/views/admin/Clients.vue'
import Directories from '@/views/admin/Directories.vue'
import Sessions from '@/views/Sessions.vue'
import Tenants from '@/views/operator/Tenants.vue'
import { router } from '@/router'
import { useSession } from '@/stores/session'
import { mountView, stubFetch } from './helpers'

// Server-side tables (go-tangra specs/032-server-side-tables, T125): every
// console table asks the server for one page with its sort, shows the
// server's total, keeps its state in the URL and goes back to page 1 when
// filters or the sort change.

/** A page answer: n rows built by row, out of total. */
function pageOf(url: string, total: number, row: (i: number) => Record<string, unknown>) {
  const u = new URL(url, 'https://console.test')
  const page = Number(u.searchParams.get('page') ?? 1)
  const size = Number(u.searchParams.get('page_size') ?? 25)
  const n = Math.max(0, Math.min(size, total - (page - 1) * size))
  return { items: Array.from({ length: n }, (_, i) => row((page - 1) * size + i)), total, page, page_size: size, sort: u.searchParams.get('sort'), order: u.searchParams.get('order') }
}
const params = (call: unknown[] | undefined) => new URL(String(call?.[0]), 'https://console.test').searchParams
const gets = (fetch: ReturnType<typeof stubFetch>, prefix: string) => fetch.mock.calls.filter((c) => String(c[0]).startsWith(prefix + '?') && ((c[1] as RequestInit | undefined)?.method ?? 'GET') === 'GET')

describe('server-paged console tables', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    useSession().apply({ user: { id: 'u1', email: 'alice@x.test' }, tenant: { id: 't1', slug: 'acme' }, roles: ['owner'], operator: true })
    await router.push('/admin/users')
    await router.isReady()
  })

  it('users: pages beyond 200 on the server, sorts server-side and resets to page 1 on search', async () => {
    const fetch = stubFetch((url) => {
      if (url.startsWith('/api/v1/admin/users?')) return { status: 200, body: pageOf(url, 260, (i) => ({ id: 'u' + i, email: `user${i}@x.test`, display_name: '', status: 'active', mfa_enabled: false, roles: [], last_signin_at: null })) }
      return { status: 200, body: [] }
    })
    await router.push({ path: '/admin/users', query: { 'users.page': '11' } })
    const w = mountView(Users)
    await flushPromises()
    let p = params(gets(fetch, '/api/v1/admin/users').at(-1))
    expect([p.get('page'), p.get('page_size'), p.get('sort'), p.get('order')]).toEqual(['11', '25', 'email', 'asc'])
    expect(w.findAll('[data-test="user-row"]').length).toBe(10) // 251–260 of 260
    expect(w.text()).toMatch(/260/)
    // Sorting by a column asks the server and starts at page 1.
    const header = w.findAll('th button').find((b) => b.text().includes('Last sign-in'))!
    await header.trigger('click')
    await flushPromises()
    p = params(gets(fetch, '/api/v1/admin/users').at(-1))
    expect([p.get('sort'), p.get('page')]).toEqual(['last_signin_at', '1'])
    expect(router.currentRoute.value.query['users.sort']).toBe('last_signin_at')
    // A search goes back to page 1 with the filter.
    await router.push({ path: '/admin/users', query: { ...router.currentRoute.value.query, 'users.page': '3' } })
    await flushPromises()
    await w.find('[data-test="search"] input').setValue('user2')
    await new Promise((r) => setTimeout(r, 300))
    await flushPromises()
    p = params(gets(fetch, '/api/v1/admin/users').at(-1))
    expect([p.get('q'), p.get('page')]).toEqual(['user2', '1'])
    w.unmount()
  })

  const tables: { name: string; view: Component; route: string; path: string; sort: string; order: string; row: (i: number) => Record<string, unknown>; rowSel: string }[] = [
    { name: 'groups', view: Groups, route: '/admin/groups', path: '/api/v1/admin/groups', sort: 'name', order: 'asc', row: (i) => ({ id: 'g' + i, name: 'Group ' + i, member_count: i, roles: [] }), rowSel: 'group-row' },
    { name: 'roles', view: Roles, route: '/admin/roles', path: '/api/v1/admin/roles', sort: 'display_name', order: 'asc', row: (i) => ({ id: 'r' + i, slug: 'role' + i, display_name: 'Role ' + i, origin: 'custom', permissions: [] }), rowSel: 'role-row' },
    { name: 'clients', view: Clients, route: '/admin/clients', path: '/api/v1/admin/clients', sort: 'display_name', order: 'asc', row: (i) => ({ client_id: 'c' + i, display_name: 'App ' + i, redirect_uris: [], public: true }), rowSel: 'client-row' },
    { name: 'directories', view: Directories, route: '/admin/directories', path: '/api/v1/admin/directories', sort: 'name', order: 'asc', row: (i) => ({ id: 'd' + i, name: 'Dir ' + i, url: 'ldaps://x', tls_mode: 'ldaps', last_test: null }), rowSel: 'directory-row' },
    { name: 'sessions', view: Sessions, route: '/sessions', path: '/api/v1/sessions', sort: 'created_at', order: 'desc', row: (i) => ({ id: 's' + i, current: i === 0, user_agent: 'ua', created_at: '2026-09-30T00:00:00Z', last_seen_at: '2026-09-30T00:00:00Z', expires_at: '2026-10-30T00:00:00Z' }), rowSel: 'session' },
    { name: 'tenants', view: Tenants, route: '/operator/tenants', path: '/api/v1/operator/tenants', sort: 'display_name', order: 'asc', row: (i) => ({ id: 't' + i, slug: 'tenant' + i, display_name: 'Tenant ' + i, status: 'active', kind: 'customer', created_at: '2026-09-30T00:00:00Z' }), rowSel: 'tenant-row' },
  ]
  for (const t of tables) {
    it(`${t.name}: asks for one page with the default sort and shows the server total`, async () => {
      const fetch = stubFetch((url) => (url.startsWith(t.path + '?') ? { status: 200, body: pageOf(url, 60, t.row) } : { status: 200, body: [] }))
      await router.push(t.route)
      const w = mountView(t.view)
      await flushPromises()
      const p = params(gets(fetch, t.path)[0])
      expect([p.get('page'), p.get('page_size'), p.get('sort'), p.get('order')]).toEqual(['1', '25', t.sort, t.order])
      expect(w.findAll(`[data-test^="${t.rowSel}"]:not([data-test="${t.name}"])`).length).toBe(25)
      expect(w.text()).toMatch(/60/)
      const next = w.findAll('button').find((b) => b.attributes('aria-label') === 'Next page')!
      await next.trigger('click')
      await flushPromises()
      expect(params(gets(fetch, t.path).at(-1)).get('page')).toBe('2')
      expect(router.currentRoute.value.query[`${t.name}.page`]).toBe('2')
      w.unmount()
    })
  }

  it('group members: newest first, paged on the server', async () => {
    const fetch = stubFetch((url) => {
      if (url === '/api/v1/admin/groups/g1') return { status: 200, body: { id: 'g1', name: 'Finance', member_count: 40, roles: [] } }
      if (url.startsWith('/api/v1/admin/groups/g1/members?')) return { status: 200, body: pageOf(url, 40, (i) => ({ user_id: 'u' + i, email: `m${i}@x.test`, display_name: '', status: 'active', avatar_url: '', added_at: '2026-09-16T00:00:00Z' })) }
      return { status: 200, body: [] }
    })
    await router.push('/admin/groups/g1')
    const w = mountView(GroupDetail)
    await flushPromises()
    const p = params(gets(fetch, '/api/v1/admin/groups/g1/members')[0])
    expect([p.get('page'), p.get('sort'), p.get('order')]).toEqual(['1', 'added_at', 'desc'])
    expect(w.findAll('[data-test="member-row"]').length).toBe(25)
    w.unmount()
  })

  it('sessions: "sign out everywhere else" ends the other sessions of every page', async () => {
    const all = Array.from({ length: 30 }, (_, i) => ({ id: 's' + i, current: i === 0, user_agent: 'ua', created_at: '2026-09-30T00:00:00Z', last_seen_at: '2026-09-30T00:00:00Z', expires_at: '2026-10-30T00:00:00Z' }))
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/sessions' && (init?.method ?? 'GET') === 'GET') return { status: 200, body: all } // unpaged: every live session
      if (url.startsWith('/api/v1/sessions?')) return { status: 200, body: pageOf(url, all.length, (i) => all[i]!) }
      return { status: 204, body: null }
    })
    await router.push('/sessions')
    const w = mountView(Sessions)
    await flushPromises()
    await w.find('[data-test="revoke-others"]').trigger('click')
    await flushPromises()
    const ok = [...document.querySelectorAll('button')].find((b) => b.textContent?.trim() === 'Sign out others') as HTMLButtonElement
    ok.click()
    await flushPromises()
    const revoked = fetch.mock.calls.filter((c) => String(c[0]).endsWith('/revoke')).map((c) => String(c[0]))
    expect(revoked.length).toBe(29)
    expect(revoked).not.toContain('/api/v1/sessions/s0/revoke')
    w.unmount()
  })
})
