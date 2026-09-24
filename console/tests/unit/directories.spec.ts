// T035 (US1, tests first): the directories page and its drawer.
// Wire format and reason vocabulary: contracts/ldap-import-api.md §A.
// Fails until T036 adds views/admin/Directories.vue, views/admin/DirectoryDrawer.vue
// and schemas/directory.ts.
import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Directories from '@/views/admin/Directories.vue'
import { directoryConnectionSchema, directoryCreateSchema } from '@/schemas/directory'
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
const openldap = {
  ...ad,
  id: 'd2',
  name: 'OpenLDAP',
  kind: 'openldap',
  url: 'ldap://dir.x.test:389',
  tls_mode: 'starttls',
  attributes: { uid: 'entryUUID', email: 'mail', display_name: 'cn', first_name: 'givenName', last_name: 'sn' },
  last_test: { at: '2026-09-22T08:00:00Z', outcome: 'tls_failed' },
}
const untested = { ...ad, id: 'd3', name: 'Legacy', last_test: null }

const bad = (r: { success: boolean; error?: { issues: { path: PropertyKey[]; message: string }[] } }) => (r.success ? [] : r.error!.issues.map((i) => i.path.join('.') + ':' + i.message))

/** Sets a native <select> inside a kit field wrapper and emits change. */
async function choose(sel: string, value: string): Promise<void> {
  const el = q<HTMLSelectElement>(`${sel} select`)
  el.value = value
  el.dispatchEvent(new Event('change'))
  await flushPromises()
}

const posted = (fetch: ReturnType<typeof stubFetch>, predicate: (c: unknown[]) => boolean) => fetch.mock.calls.find((c) => c[1]?.method !== 'GET' && predicate(c))

describe('directory connection schema', () => {
  const minimal = {
    name: 'Corp AD',
    kind: 'active_directory',
    url: 'ldaps://dc.corp.test:636',
    tls_mode: 'ldaps',
    bind_dn: 'cn=reader,dc=corp,dc=test',
    base_dn: 'dc=corp,dc=test',
  }

  it('normalises a valid input and defaults the optional fields', () => {
    expect(directoryConnectionSchema.parse({ ...minimal, name: '  Corp AD  ' })).toEqual({
      name: 'Corp AD',
      kind: 'active_directory',
      url: 'ldaps://dc.corp.test:636',
      tls_mode: 'ldaps',
      allow_tls12: false,
      ca_pem: undefined,
      bind_dn: 'cn=reader,dc=corp,dc=test',
      bind_password: undefined,
      base_dn: 'dc=corp,dc=test',
      base_filter: undefined,
      attributes: undefined,
      size_limit: undefined,
      time_limit_seconds: undefined,
    })
    const blank = directoryConnectionSchema.parse({ ...minimal, size_limit: '', time_limit_seconds: undefined })
    expect(blank.size_limit).toBeUndefined()
    expect(blank.time_limit_seconds).toBeUndefined()
    expect(directoryConnectionSchema.parse({ ...minimal, attributes: { uid: 'entryUUID' }, size_limit: 250 })).toMatchObject({ attributes: { uid: 'entryUUID' }, size_limit: 250 })
  })

  it('refuses bad schemes, lengths and limits with field errors', () => {
    expect(bad(directoryConnectionSchema.safeParse({ ...minimal, url: 'http://dc.corp.test' }))).toEqual(['url:Enter an ldap:// or ldaps:// URL.'])
    expect(bad(directoryConnectionSchema.safeParse({ ...minimal, url: '' }))[0]).toMatch(/^url:/)
    expect(bad(directoryConnectionSchema.safeParse({ ...minimal, name: 'x'.repeat(81) }))).toEqual(['name:At most 80 characters.'])
    expect(bad(directoryConnectionSchema.safeParse({ ...minimal, bind_password: 'x'.repeat(1025) }))).toEqual(['bind_password:At most 1024 characters.'])
    expect(bad(directoryConnectionSchema.safeParse({ ...minimal, size_limit: 0 }))).toEqual(['size_limit:Between 1 and 1000.'])
    expect(bad(directoryConnectionSchema.safeParse({ ...minimal, size_limit: 1001 }))).toEqual(['size_limit:Between 1 and 1000.'])
    expect(bad(directoryConnectionSchema.safeParse({ ...minimal, time_limit_seconds: 61 }))).toEqual(['time_limit_seconds:Between 1 and 60.'])
    expect(bad(directoryConnectionSchema.safeParse({ ...minimal, kind: 'novell' }))[0]).toMatch(/^kind:/)
    expect(bad(directoryConnectionSchema.safeParse({ ...minimal, tls_mode: 'tls' }))[0]).toMatch(/^tls_mode:/)
  })

  it('rejects URL credentials and invalid attributes, and preserves explicit clearing and secret whitespace', () => {
    expect(directoryConnectionSchema.safeParse({ ...minimal, url: 'ldaps://reader:secret@dc.corp.test' }).success).toBe(false)
    expect(directoryConnectionSchema.safeParse({ ...minimal, attributes: { uid: 'uid)(mail=*' } }).success).toBe(false)
    expect(directoryConnectionSchema.safeParse({ ...minimal, ca_pem: 'x'.repeat(65537) }).success).toBe(false)
    expect(directoryConnectionSchema.parse({ ...minimal, bind_password: ' secret ', ca_pem: '', base_filter: '' })).toMatchObject({ bind_password: ' secret ', ca_pem: '', base_filter: '' })
  })

  it('requires the password only on create; on update blank means keep', () => {
    expect(bad(directoryCreateSchema.safeParse(minimal))).toEqual(['bind_password:Enter the bind password.'])
    expect(directoryCreateSchema.safeParse({ ...minimal, bind_password: 's3cret' }).success).toBe(true)
    const kept = directoryConnectionSchema.parse({ ...minimal, bind_password: '' })
    expect(kept.bind_password).toBeUndefined()
  })
})

describe('directories console', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    useSession().apply({ user: { id: 'u1', email: 'a@x.test' }, tenant: { id: 't1' }, roles: ['owner'] })
    await router.push('/admin/directories')
    await router.isReady()
  })

  it('lists connections with URL, TLS mode and a last-test chip per row', async () => {
    stubFetch((url) => (url === '/api/v1/admin/directories' ? { status: 200, body: { items: [ad, openldap, untested] } } : { status: 404, body: { reason: 'not_found' } }))
    const w = mountView(Directories)
    await flushPromises()
    expect(router.currentRoute.value.name).toBe('admin-directories')
    const rows = w.findAll('[data-test="directory-row"]')
    expect(rows.length).toBe(3)
    expect(rows[0]!.text()).toContain('Corp AD')
    expect(rows[0]!.find('[data-test="directory-url"]').text()).toBe('ldaps://dc.corp.test:636')
    expect(rows[0]!.find('[data-test="directory-tls"]').text()).toBe('ldaps')
    const chips = w.findAll('[data-test="last-test"]')
    expect(chips.length).toBe(3)
    expect(chips[0]!.text()).toMatch(/ok/i)
    expect(chips[0]!.attributes('title')).toBe('2026-09-23T08:00:00Z')
    expect(chips[1]!.text()).toMatch(/TLS failed/i)
    expect(chips[1]!.attributes('title')).toBe('2026-09-22T08:00:00Z')
    expect(chips[2]!.text()).toMatch(/never tested/i)
    w.unmount()
  })

  it('validates the drawer with zod, fills the mapping presets per kind and creates a connection', async () => {
    const fetch = stubFetch((url, init) =>
      url === '/api/v1/admin/directories' && init?.method === 'POST'
        ? { status: 201, body: { ...openldap, id: 'd9', name: 'New dir' } }
        : { status: 200, body: { items: [] } },
    )
    const w = mountView(Directories)
    await flushPromises()
    await w.find('[data-test="new-directory"]').trigger('click')
    await flushPromises()
    expect(q('[data-test="directory-drawer"]')).not.toBeNull()
    // Empty submit: zod errors inline, nothing posted.
    await click('[data-test="save-directory"]')
    expect(posted(fetch, (c) => String(c[0]) === '/api/v1/admin/directories')).toBeUndefined()
    expect(q('[data-test="directory-name"] [role=alert]').textContent).toBeTruthy()
    expect(q('[data-test="directory-url"] [role=alert]').textContent).toBeTruthy()
    // Kind presets fill only empty mapping fields.
    await choose('[data-test="directory-kind"]', 'active_directory')
    expect(q<HTMLInputElement>('[data-test="attr-uid"] input').value).toBe('objectGUID')
    expect(q<HTMLInputElement>('[data-test="attr-email"] input').value).toBe('mail')
    expect(q<HTMLInputElement>('[data-test="attr-display-name"] input').value).toBe('displayName')
    expect(q<HTMLInputElement>('[data-test="attr-first-name"] input').value).toBe('givenName')
    expect(q<HTMLInputElement>('[data-test="attr-last-name"] input').value).toBe('sn')
    await type('[data-test="attr-uid"] input', 'objectSid')
    await type('[data-test="attr-display-name"] input', '')
    await choose('[data-test="directory-kind"]', 'openldap')
    expect(q<HTMLInputElement>('[data-test="attr-uid"] input').value).toBe('objectSid')
    expect(q<HTMLInputElement>('[data-test="attr-display-name"] input').value).toBe('cn')
    await choose('[data-test="directory-kind"]', 'other')
    expect(q<HTMLInputElement>('[data-test="attr-uid"] input').value).toBe('objectSid')
    // Save posts the zod-normalised values, including the preset mapping.
    await type('[data-test="directory-name"] input', 'New dir')
    await type('[data-test="directory-url"] input', 'ldap://dir.x.test:389')
    await choose('[data-test="directory-tls-mode"]', 'starttls')
    await type('[data-test="bind-dn"] input', 'cn=reader,dc=x,dc=test')
    await type('[data-test="base-dn"] input', 'dc=x,dc=test')
    await type('[data-test="bind-password"] input', 's3cret')
    await click('[data-test="save-directory"]')
    const call = posted(fetch, (c) => String(c[0]) === '/api/v1/admin/directories')
    expect(body(call)).toEqual({
      name: 'New dir',
      kind: 'other',
      url: 'ldap://dir.x.test:389',
      tls_mode: 'starttls',
      allow_tls12: false,
      bind_dn: 'cn=reader,dc=x,dc=test',
      base_dn: 'dc=x,dc=test',
      bind_password: 's3cret',
      attributes: { uid: 'objectSid', email: 'mail', display_name: 'cn', first_name: 'givenName', last_name: 'sn' },
    })
    expect(w.findAll('[data-test="directory-row"]').length).toBe(1)
    w.unmount()
  })

  it('keeps the stored password when the write-only field is left blank on edit', async () => {
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/admin/directories/d1' && (init?.method ?? 'GET') === 'GET') return { status: 200, body: { ...ad, ca_pem: '' } }
      if (String(url).startsWith('/api/v1/admin/directories/d1') && init?.method === 'PUT') return { status: 200, body: { ...ad, name: 'Corp AD 2' } }
      return { status: 200, body: { items: [ad, openldap] } }
    })
    const w = mountView(Directories)
    await flushPromises()
    const firstRow = () => w.findAll('[data-test="directory-row"]')[0]!
    await firstRow().find('[data-test="edit"]').trigger('click')
    await flushPromises()
    expect(q<HTMLInputElement>('[data-test="directory-name"] input').value).toBe('Corp AD')
    const pw = q<HTMLInputElement>('[data-test="bind-password"] input')
    expect(pw.value).toBe('')
    expect(pw.type).toBe('password')
    expect(pw.autocomplete).toBe('new-password')
    expect(q('[data-test="bind-password"] .helper-text').textContent).toBe('stored — leave blank to keep; required when the URL, TLS mode or CA changes')
    await type('[data-test="directory-name"] input', 'Corp AD 2')
    await click('[data-test="save-directory"]')
    const call = posted(fetch, (c) => String(c[0]) === '/api/v1/admin/directories/d1')
    expect(call).toBeTruthy()
    expect(body(call)).toMatchObject({ name: 'Corp AD 2', kind: 'active_directory' })
    expect(body(call)).not.toHaveProperty('bind_password')
    expect(firstRow().text()).toContain('Corp AD 2')
    w.unmount()
  })

  it('tests a new connection from the drawer and reports success with the TLS version', async () => {
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/admin/directories/test' && init?.method === 'POST') return { status: 200, body: { ok: true, step: null, reason: null, tls: { version: 'TLS 1.3', peer_subject: 'CN=dc.corp.test' }, duration_ms: 95 } }
      return { status: 200, body: { items: [] } }
    })
    const w = mountView(Directories)
    await flushPromises()
    await w.find('[data-test="new-directory"]').trigger('click')
    await flushPromises()
    await type('[data-test="directory-name"] input', 'Trial')
    await type('[data-test="directory-url"] input', 'ldaps://dc.corp.test:636')
    await choose('[data-test="directory-kind"]', 'active_directory')
    await choose('[data-test="directory-tls-mode"]', 'ldaps')
    await type('[data-test="bind-dn"] input', 'cn=reader,dc=corp,dc=test')
    await type('[data-test="base-dn"] input', 'dc=corp,dc=test')
    await type('[data-test="bind-password"] input', 's3cret')
    await click('[data-test="test-connection"]')
    const call = posted(fetch, (c) => String(c[0]) === '/api/v1/admin/directories/test')
    expect(call).toBeTruthy()
    const sent = body(call)
    expect(sent).toMatchObject({ name: 'Trial', bind_password: 's3cret' })
    expect('connection_id' in sent).toBe(false)
    expect(q('[data-test="test-result"]').textContent).toMatch(/Connection OK/i)
    expect(q('[data-test="test-result"]').textContent).toContain('TLS 1.3')
    w.unmount()
  })

  it('shows the failing step and reason when the test of a saved connection fails', async () => {
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/admin/directories/test' && init?.method === 'POST') return { status: 200, body: { ok: false, step: 'tls', reason: 'tls_failed', tls: null, duration_ms: 240 } }
      if (url === '/api/v1/admin/directories/d1' && (init?.method ?? 'GET') === 'GET') return { status: 200, body: { ...ad, ca_pem: '' } }
      return { status: 200, body: { items: [ad] } }
    })
    const w = mountView(Directories)
    await flushPromises()
    await w.find('[data-test="directory-row"] [data-test="edit"]').trigger('click')
    await flushPromises()
    await click('[data-test="test-connection"]')
    const call = posted(fetch, (c) => String(c[0]) === '/api/v1/admin/directories/test')
    expect(call).toBeTruthy()
    const sent = body(call)
    expect(sent).toMatchObject({ connection_id: 'd1' })
    expect('bind_password' in sent).toBe(false)
    expect(q('[data-test="test-step"]').textContent).toBe('TLS')
    expect(q('[data-test="test-reason"]').textContent).toBe('The TLS handshake failed.')
    w.unmount()
  })

  it('loads the saved CA, allows clearing it, and keeps a refused edit open for correction', async () => {
    const fetch = stubFetch((url, init) => {
      if (url === '/api/v1/admin/directories/d1' && init?.method === 'GET') return { status: 200, body: { ...ad, ca_pem: 'saved public CA' } }
      if (init?.method === 'PUT') return { status: 400, body: { reason: 'invalid_ca' } }
      return { status: 200, body: { items: [ad] } }
    })
    const w = mountView(Directories)
    await flushPromises()
    await w.find('[data-test="edit"]').trigger('click')
    await flushPromises()
    expect(q<HTMLTextAreaElement>('#ca_pem').value).toBe('saved public CA')
    await type('#ca_pem', '')
    await click('[data-test="save-directory"]')
    expect(body(posted(fetch, (c) => (c[1] as RequestInit).method === 'PUT'))).toMatchObject({ ca_pem: '' })
    expect(q('[data-test="directory-drawer"]').textContent).toContain('Enter a valid PEM CA certificate bundle.')
    expect(q<HTMLInputElement>('[data-test="bind-password"] input').value).toBe('')
    w.unmount()
  })

  it('confirms deletion with the note that imported users stay, then removes the row', async () => {
    const fetch = stubFetch((url, init) =>
      url === '/api/v1/admin/directories/d1/remove' && init?.method === 'POST'
        ? { status: 204, body: null }
        : { status: 200, body: { items: [ad, openldap] } },
    )
    const w = mountView(Directories)
    await flushPromises()
    await w.find('[data-test="directory-row"] [data-test="delete-directory"]').trigger('click')
    await flushPromises()
    expect(q('[data-test="delete-dialog"]')).not.toBeNull()
    expect(q('[data-test="delete-summary"]').textContent).toMatch(/Users already imported from Corp AD stay/)
    await click('[data-test="delete-dialog"] [data-test="confirm-delete"]')
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/directories/d1/remove', expect.objectContaining({ method: 'POST' }))
    expect(w.findAll('[data-test="directory-row"]').length).toBe(1)
    w.unmount()
  })
})
