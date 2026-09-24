// T051 (US2, tests first): the directory import page — filter/base/scope search,
// preview with per-entry status, selection limited to new/imported, truncation
// notice and the import summary with skip reasons.
// Wire format and reason vocabulary: contracts/ldap-import-api.md §A.
// Fails until T052 adds views/admin/DirectoryImport.vue, the
// /admin/directories/import route, directorySearchSchema in schemas/directory.ts,
// `imported` in api/vocab.ts and the registered skip-reason wording in api/client.ts.
import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import DirectoryImport from '@/views/admin/DirectoryImport.vue'
import { directorySearchSchema, directoryImportSchema } from '@/schemas/directory'
import { router } from '@/router'
import { useSession } from '@/stores/session'
import { body, click, mountView, q, stubFetch, type } from './helpers'

const ad = {
  id: 'd1',
  name: 'Corp AD',
  kind: 'active_directory',
  url: 'ldaps://dc.corp.test:636',
  tls_mode: 'ldaps',
  allow_tls12: false,
  ca_pem_set: false,
  bind_dn: 'cn=reader,dc=corp,dc=test',
  bind_password_set: true,
  base_dn: 'dc=corp,dc=test',
  base_filter: '(objectClass=user)',
  attributes: { uid: 'objectGUID', email: 'mail', display_name: 'displayName', first_name: 'givenName', last_name: 'sn' },
  size_limit: 500,
  time_limit_seconds: 15,
  last_test: { at: '2026-09-23T08:00:00Z', outcome: 'ok' },
  created_at: '2026-09-01T00:00:00Z',
  updated_at: '2026-09-23T08:00:00Z',
}
const openldap = { ...ad, id: 'd2', name: 'OpenLDAP', kind: 'openldap' }

const entry = (uid: string, displayName: string, status: string, extra: Record<string, unknown> = {}) => ({
  uid,
  dn: `cn=${uid},ou=eng,dc=corp,dc=test`,
  email: `${uid}@corp.test`,
  display_name: displayName,
  first_name: displayName.split(' ')[0],
  last_name: displayName.split(' ')[1] ?? '',
  status,
  user_id: null,
  reason: null,
  ...extra,
})
// One row per preview status; only new/imported rows may be selected.
const preview = {
  items: [
    entry('ada', 'Ada Lovelace', 'new'),
    entry('ben', 'Ben Bitdiddle', 'existing_user', { user_id: 'u2' }),
    entry('cy', 'Cy By', 'imported', { user_id: 'u3' }),
    entry('didi', 'Di Di', 'invalid', { email: null, reason: 'no_email' }),
    entry('eli', 'Eli Extra', 'new'),
    entry('fay', 'Fay Finkel', 'new'),
  ],
  truncated: false,
  out_of_scope: 1,
  effective_filter: '(&(objectClass=user)(mail=*))',
}

const bad = (r: { success: boolean; error?: { issues: { path: PropertyKey[]; message: string }[] } }) => (r.success ? [] : r.error!.issues.map((i) => i.path.join('.') + ':' + i.message))

/** Sets a native <select> inside a kit field wrapper and emits change. */
async function choose(sel: string, value: string): Promise<void> {
  const el = q<HTMLSelectElement>(`${sel} select`)
  el.value = value
  el.dispatchEvent(new Event('change'))
  await flushPromises()
}

const posted = (fetch: ReturnType<typeof stubFetch>, predicate: (c: unknown[]) => boolean) => fetch.mock.calls.find((c) => c[1]?.method !== 'GET' && predicate(c))
const searchCalls = (fetch: ReturnType<typeof stubFetch>) => fetch.mock.calls.filter((c) => String(c[0]).endsWith('/search'))

describe('directory search schema', () => {
  it('trims set fields and drops blank ones', () => {
    expect(directorySearchSchema.parse({ filter: '  (mail=*)  ', base: ' ou=Eng,dc=corp,dc=test ', scope: 'one' })).toEqual({ filter: '(mail=*)', base: 'ou=Eng,dc=corp,dc=test', scope: 'one' })
    const blank = directorySearchSchema.parse({ filter: '', base: '', scope: '' })
    expect(blank.filter).toBeUndefined()
    expect(blank.base).toBeUndefined()
    expect(blank.scope).toBeUndefined()
    expect(directorySearchSchema.parse({ filter: '(objectClass=person)' })).toEqual({ filter: '(objectClass=person)' })
  })

  it('caps filter and base length and accepts only the one/sub scopes', () => {
    expect(bad(directorySearchSchema.safeParse({ filter: 'x'.repeat(4097) }))).toEqual(['filter:At most 4096 characters.'])
    expect(bad(directorySearchSchema.safeParse({ base: 'x'.repeat(1025) }))).toEqual(['base:At most 1024 characters.'])
    expect(bad(directorySearchSchema.safeParse({ scope: 'base' }))[0]).toMatch(/^scope:/)
    expect(directorySearchSchema.safeParse({ filter: 'x'.repeat(4096), base: 'y'.repeat(1024), scope: 'sub' }).success).toBe(true)
  })
})

describe('directory import console', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    useSession().apply({ user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: ['owner'] })
    await router.push('/admin/directories/import')
    await router.isReady()
  })

  it('picks a connection, searches with filter/base/scope and renders the preview', async () => {
    const fetch = stubFetch((url, init) =>
      url === '/api/v1/admin/directories/d1/search' && init?.method === 'POST'
        ? { status: 200, body: preview }
        : { status: 200, body: { items: [ad, openldap] } },
    )
    const w = mountView(DirectoryImport)
    await flushPromises()
    expect(router.currentRoute.value.name).toBe('admin-directory-import')
    // Connection picker lists the tenant's directories; the form stays hidden until one is chosen.
    expect(w.find('[data-test="filter"]').exists()).toBe(false)
    await choose('[data-test="connection"]', 'd1')
    expect(w.find('[data-test="filter"]').exists()).toBe(true)
    await type('[data-test="filter"] input', '(mail=*)')
    await type('[data-test="base"] input', 'ou=Eng,dc=corp,dc=test')
    await choose('[data-test="scope"]', 'one')
    await click('[data-test="search-directory"]')
    expect(body(posted(fetch, (c) => String(c[0]).endsWith('/search')))).toEqual({ filter: '(mail=*)', base: 'ou=Eng,dc=corp,dc=test', scope: 'one' })
    const rows = w.findAll('[data-test="preview-row"]')
    expect(rows.length).toBe(6)
    expect(rows.map((r) => r.find('[data-test="preview-name"]').text())).toEqual(['Ada Lovelace', 'Ben Bitdiddle', 'Cy By', 'Di Di', 'Eli Extra', 'Fay Finkel'])
    expect(rows.map((r) => r.find('[data-test="preview-status"]').text())).toEqual(['New', 'Existing user', 'Imported', 'Invalid', 'New', 'New'])
    expect(rows[3]!.find('[data-test="preview-reason"]').text()).toBe('The directory entry has no email address.')
    expect(q('[data-test="effective-filter"]').textContent).toContain('(&(objectClass=user)(mail=*))')
    expect(w.find('[data-test="truncation"]').exists()).toBe(false)
    expect(q<HTMLButtonElement>('[data-test="import"]').disabled).toBe(true)
    w.unmount()
  })

  it('omits blank base and scope from the search request', async () => {
    const fetch = stubFetch((url, init) =>
      url === '/api/v1/admin/directories/d1/search' && init?.method === 'POST'
        ? { status: 200, body: { ...preview, items: [] } }
        : { status: 200, body: { items: [ad, openldap] } },
    )
    const w = mountView(DirectoryImport)
    await flushPromises()
    await choose('[data-test="connection"]', 'd1')
    await type('[data-test="filter"] input', '(objectClass=person)')
    await click('[data-test="search-directory"]')
    expect(body(posted(fetch, (c) => String(c[0]).endsWith('/search')))).toEqual({ filter: '(objectClass=person)' })
    w.unmount()
  })

  it('shows the server parse error for an invalid filter and no preview', async () => {
    stubFetch((url, init) =>
      url === '/api/v1/admin/directories/d1/search' && init?.method === 'POST'
        ? { status: 400, body: { reason: 'invalid_filter', message: 'ldap.filter:1: unexpected end of input' } }
        : { status: 200, body: { items: [ad, openldap] } },
    )
    const w = mountView(DirectoryImport)
    await flushPromises()
    await choose('[data-test="connection"]', 'd1')
    await type('[data-test="filter"] input', '(objectClass=person')
    await click('[data-test="search-directory"]')
    expect(q('[data-test="search-error"]').textContent).toBe('ldap.filter:1: unexpected end of input')
    expect(w.findAll('[data-test="preview-row"]').length).toBe(0)
    w.unmount()
  })

  it('shows the registered base error when the base leaves the connection base', async () => {
    stubFetch((url, init) =>
      url === '/api/v1/admin/directories/d1/search' && init?.method === 'POST'
        ? { status: 400, body: { reason: 'invalid_base' } }
        : { status: 200, body: { items: [ad, openldap] } },
    )
    const w = mountView(DirectoryImport)
    await flushPromises()
    await choose('[data-test="connection"]', 'd1')
    await type('[data-test="filter"] input', '(mail=*)')
    await type('[data-test="base"] input', 'ou=Else,dc=corp,dc=test')
    await click('[data-test="search-directory"]')
    expect(q('[data-test="search-error"]').textContent).toBe('Enter a valid search base DN.')
    w.unmount()
  })

  it('selects only new and imported entries', async () => {
    stubFetch((url, init) =>
      url === '/api/v1/admin/directories/d1/search' && init?.method === 'POST'
        ? { status: 200, body: preview }
        : { status: 200, body: { items: [ad] } },
    )
    const w = mountView(DirectoryImport)
    await flushPromises()
    await choose('[data-test="connection"]', 'd1')
    await type('[data-test="filter"] input', '(mail=*)')
    await click('[data-test="search-directory"]')
    const box = (i: number) => w.findAll('[data-test="preview-row"]')[i]!.find<HTMLInputElement>('input[type=checkbox]').element
    // existing_user and invalid rows carry a disabled checkbox; new/imported do not.
    expect(box(0).disabled).toBe(false)
    expect(box(1).disabled).toBe(true)
    expect(box(2).disabled).toBe(false)
    expect(box(3).disabled).toBe(true)
    expect(box(4).disabled).toBe(false)
    box(1).click()
    await flushPromises()
    expect(box(1).checked).toBe(false)
    expect(q<HTMLButtonElement>('[data-test="import"]').disabled).toBe(true)
    // Selecting one new entry enables the import button.
    box(0).click()
    await flushPromises()
    expect(box(0).checked).toBe(true)
    expect(q<HTMLButtonElement>('[data-test="import"]').disabled).toBe(false)
    // Select all checks only the four new/imported rows.
    await click('[data-test="select-all"]')
    expect([0, 1, 2, 3, 4, 5].map((i) => box(i).checked)).toEqual([true, false, true, false, true, true])
    w.unmount()
  })

  it('imports the selection and reports created/updated/skipped/failed with reasons', async () => {
    const fetch = stubFetch((url, init) => {
      if (String(url).endsWith('/import') && init?.method === 'POST')
        return {
          status: 200,
          body: {
            created: [{ uid: 'ada', user_id: 'u9' }],
            updated: [{ uid: 'cy', user_id: 'u3' }],
            skipped: [{ uid: 'eli', reason: 'email_in_use' }],
            failed: [{ uid: 'fay', reason: 'timeout' }],
          },
        }
      if (String(url).endsWith('/search') && init?.method === 'POST') return { status: 200, body: preview }
      return { status: 200, body: { items: [ad] } }
    })
    const w = mountView(DirectoryImport)
    await flushPromises()
    await choose('[data-test="connection"]', 'd1')
    await type('[data-test="filter"] input', '(mail=*)')
    await click('[data-test="search-directory"]')
    await click('[data-test="select-all"]')
    await click('[data-test="import"]')
    expect(body(posted(fetch, (c) => String(c[0]).endsWith('/import')))).toEqual({ uids: ['ada', 'cy', 'eli', 'fay'] })
    await flushPromises()
    const summary = q('[data-test="import-summary"]')
    expect(summary.textContent).toContain('1 created')
    expect(summary.textContent).toContain('1 updated')
    expect(summary.textContent).toContain('1 skipped')
    expect(summary.textContent).toContain('1 failed')
    expect(w.findAll('[data-test="import-issue"]').map((i) => i.text())).toEqual([
      'Eli Extra: That email address already belongs to a user.',
      'Fay Finkel: The directory request timed out.',
    ])
    // The preview refreshes after the import and the selection is cleared.
    expect(searchCalls(fetch).length).toBe(2)
    expect(q<HTMLButtonElement>('[data-test="import"]').disabled).toBe(true)
    w.unmount()
  })

  it('shows a truncation notice when the result hit the size limit', async () => {
    stubFetch((url, init) =>
      url === '/api/v1/admin/directories/d1/search' && init?.method === 'POST'
        ? { status: 200, body: { ...preview, items: preview.items.slice(0, 2), truncated: true } }
        : { status: 200, body: { items: [ad] } },
    )
    const w = mountView(DirectoryImport)
    await flushPromises()
    await choose('[data-test="connection"]', 'd1')
    await type('[data-test="filter"] input', '(mail=*)')
    await click('[data-test="search-directory"]')
    expect(w.findAll('[data-test="preview-row"]').length).toBe(2)
    expect(q('[data-test="truncation"]').textContent).toMatch(/[Mm]ore entries matched/)
    w.unmount()
  })
})


describe('directory import limits', () => {
  it('requires between one and 500 unique identifiers', () => {
    expect(directoryImportSchema.safeParse({ uids: [] }).success).toBe(false)
    expect(directoryImportSchema.safeParse({ uids: ['same', 'same'] }).success).toBe(false)
    expect(directoryImportSchema.safeParse({ uids: [''] }).success).toBe(false)
    const uids = Array.from({ length: 500 }, (_, i) => String(i))
    expect(directoryImportSchema.parse({ uids })).toEqual({ uids })
    expect(directoryImportSchema.safeParse({ uids: [...uids, 'extra'] }).success).toBe(false)
  })
})
