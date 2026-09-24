// T061 (US3, tests first): activation of imported users from the users page —
// per-row Activate / Remove actions, the ActivateDrawer role/group pickers
// (shared with InviteDialog), bulk selection limited to imported rows, the
// per-user failure summary, the whole-request self_escalation message, the
// imported e-mail removal confirm and Resend for invited users carrying an
// invitation_id.
// Wire format and reason vocabulary: contracts/ldap-import-api.md §A.
// Fails until T062 adds views/admin/ActivateDrawer.vue, the row actions /
// selection in views/admin/Users.vue, activateSchema in schemas/directory.ts
// and the invalid_state wording in api/client.ts.
import { beforeEach, describe, expect, it } from 'vitest'
import { flushPromises } from '@vue/test-utils'
import { createPinia, setActivePinia } from 'pinia'
import Users from '@/views/admin/Users.vue'
import { activateSchema } from '@/schemas/directory'
import { router } from '@/router'
import { useSession } from '@/stores/session'
import { body, click, mountView, q, stubFetch } from './helpers'

const roles = [
  { id: 'r-admin', slug: 'admin', display_name: 'Admin', builtin: true, permissions: [] },
  { id: 'r-member', slug: 'member', display_name: 'Member', builtin: true, permissions: [] },
]
const group = { id: 'g1', name: 'Engineering', member_count: 2, roles: [] }

const user = (id: string, email: string, status: string, extra: Record<string, unknown> = {}) => ({
  id,
  email,
  display_name: email.split('@')[0]!.replace('.', ' '),
  status,
  mfa_enabled: false,
  roles: [],
  last_signin_at: null,
  invitation_id: null,
  directory: null,
  ...extra,
})
const ada = user('u1', 'ada@x.test', 'active', { display_name: 'Ada', roles: ['owner'] })
const ben = user('u2', 'ben@x.test', 'deactivated')
const cy = user('u3', 'cy@corp.test', 'imported', {
  display_name: 'Cy By',
  directory: { connection_id: 'd1', connection_name: 'Corp AD', directory_uid: 'abc-123', last_imported_at: '2026-09-23T08:00:00Z' },
})
const didi = user('u4', 'didi@corp.test', 'imported')
const eli = user('u5', 'eli@x.test', 'invited', { invitation_id: 'inv-9' })
const fay = user('u6', 'fay@x.test', 'invited')

/** GET calls of the users list (not the activate/remove sub-resources). */
const listGets = (fetch: ReturnType<typeof stubFetch>) => fetch.mock.calls.filter((c) => /^\/api\/v1\/admin\/users($|\?)/.test(String(c[0]))).length
/** Checkboxes of one drawer fieldset; the drawer teleports to <body>, so this is document-wide. */
const pickerBoxes = (test: string) => [...document.querySelectorAll<HTMLInputElement>(`[data-test="${test}"] input[type=checkbox]`)]
async function pick(test: string, i: number): Promise<void> {
  pickerBoxes(test)[i]!.click()
  await flushPromises()
}

describe('activate schema', () => {
  it('requires 1..100 unique user ids and at most 50 groups', () => {
    expect(activateSchema.parse({ user_ids: ['u3'] })).toEqual({ user_ids: ['u3'] })
    expect(activateSchema.parse({ user_ids: ['u3', 'u4'], role_ids: ['r-member'], group_ids: ['g1'] })).toEqual({ user_ids: ['u3', 'u4'], role_ids: ['r-member'], group_ids: ['g1'] })
    expect(activateSchema.safeParse({ user_ids: [] }).success).toBe(false)
    expect(activateSchema.safeParse({ user_ids: [''] }).success).toBe(false)
    expect(activateSchema.safeParse({ user_ids: ['u3', 'u3'] }).success).toBe(false)
    const hundred = Array.from({ length: 100 }, (_, i) => `u${i}`)
    expect(activateSchema.parse({ user_ids: hundred }).user_ids).toHaveLength(100)
    expect(activateSchema.safeParse({ user_ids: [...hundred, 'u100'] }).success).toBe(false)
    const fifty = Array.from({ length: 50 }, (_, i) => `g${i}`)
    expect(activateSchema.parse({ user_ids: ['u3'], group_ids: fifty }).group_ids).toHaveLength(50)
    expect(activateSchema.safeParse({ user_ids: ['u3'], group_ids: [...fifty, 'g50'] }).success).toBe(false)
  })
})

describe('users: activate imported, remove imported, resend invitation', () => {
  beforeEach(async () => {
    setActivePinia(createPinia())
    useSession().apply({ user: { id: 'u1', email: 'ada@x.test' }, tenant: { id: 't1', slug: 'acme' }, roles: ['owner'] })
    await router.push('/admin/users')
    await router.isReady()
  })

  it('offers Activate and Remove only on imported rows, Resend only on invited rows with an invitation_id', async () => {
    stubFetch((url) => {
      if (String(url).startsWith('/api/v1/admin/users')) return { status: 200, body: { items: [ada, ben, cy, didi, eli, fay] } }
      if (String(url).startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Users)
    await flushPromises()
    const rows = w.findAll('[data-test="user-row"]')
    expect(rows.length).toBe(6)
    const offered = (i: number) => ({
      activate: rows[i]!.find('[data-test="activate"]').exists(),
      remove: rows[i]!.find('[data-test="remove-imported"]').exists(),
      resend: rows[i]!.find('[data-test="resend"]').exists(),
    })
    expect(offered(0)).toEqual({ activate: false, remove: false, resend: false }) // active
    expect(offered(1)).toEqual({ activate: false, remove: false, resend: false }) // deactivated
    expect(offered(2)).toEqual({ activate: true, remove: true, resend: false }) // imported
    expect(offered(3)).toEqual({ activate: true, remove: true, resend: false }) // imported
    expect(offered(4)).toEqual({ activate: false, remove: false, resend: true }) // invited + invitation_id
    expect(offered(5)).toEqual({ activate: false, remove: false, resend: false }) // invited without invitation_id
    w.unmount()
  })

  it('activates one imported user from the drawer with chosen roles and groups', async () => {
    const fetch = stubFetch((url, init) => {
      if (String(url) === '/api/v1/admin/users/activate' && init?.method === 'POST')
        return { status: 200, body: { items: [{ user_id: 'u3', outcome: 'invited', invitation_id: 'inv-1', reason: null }] } }
      if (String(url).startsWith('/api/v1/admin/users')) return { status: 200, body: { items: [ada, cy] } }
      if (String(url).startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      if (String(url).startsWith('/api/v1/admin/groups')) return { status: 200, body: { items: [group] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Users)
    await flushPromises()
    await click('[data-test="activate"]')
    // The drawer names its target and lists roles and groups like the invite dialog.
    expect(q('[data-test="activate-drawer"]')).toBeTruthy()
    expect(q('[data-test="activate-targets"]').textContent).toContain('cy@corp.test')
    expect(pickerBoxes('activate-roles').length).toBe(2)
    expect(pickerBoxes('activate-groups').length).toBe(1)
    await pick('activate-roles', 1)
    await pick('activate-groups', 0)
    await click('[data-test="activate-send"]')
    const call = fetch.mock.calls.find((c) => String(c[0]) === '/api/v1/admin/users/activate')
    expect(body(call)).toEqual({ user_ids: ['u3'], role_ids: ['r-member'], group_ids: ['g1'] })
    await flushPromises()
    // Success: the drawer closes, the summary counts invitations, the list reloads.
    expect(q('[data-test="activate-drawer"]')).toBeNull()
    expect(q('[data-test="activate-summary"]').textContent).toBe('Activation finished: 1 invited, 0 failed.')
    expect(document.querySelectorAll('[data-test="activate-failure"]')).toHaveLength(0)
    expect(listGets(fetch)).toBe(2)
    w.unmount()
  })

  it('posts only user_ids and an empty role list when no picks are made', async () => {
    const fetch = stubFetch((url, init) => {
      if (String(url) === '/api/v1/admin/users/activate' && init?.method === 'POST')
        return { status: 200, body: { items: [{ user_id: 'u3', outcome: 'invited', invitation_id: 'inv-1', reason: null }] } }
      if (String(url).startsWith('/api/v1/admin/users')) return { status: 200, body: { items: [cy] } }
      if (String(url).startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      if (String(url).startsWith('/api/v1/admin/groups')) return { status: 200, body: { items: [group] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Users)
    await flushPromises()
    await click('[data-test="activate"]')
    await click('[data-test="activate-send"]')
    const call = fetch.mock.calls.find((c) => String(c[0]) === '/api/v1/admin/users/activate')
    expect(body(call)).toEqual({ user_ids: ['u3'], role_ids: [] })
    w.unmount()
  })

  it('limits the selection to imported rows and activates the selection in bulk', async () => {
    const fetch = stubFetch((url, init) => {
      if (String(url) === '/api/v1/admin/users/activate' && init?.method === 'POST')
        return {
          status: 200,
          body: {
            items: [
              { user_id: 'u3', outcome: 'invited', invitation_id: 'inv-1', reason: null },
              { user_id: 'u4', outcome: 'invited', invitation_id: 'inv-2', reason: null },
            ],
          },
        }
      if (String(url).startsWith('/api/v1/admin/users')) return { status: 200, body: { items: [ada, cy, didi, eli] } }
      if (String(url).startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      if (String(url).startsWith('/api/v1/admin/groups')) return { status: 200, body: { items: [group] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Users)
    await flushPromises()
    const box = (i: number) => w.findAll('[data-test="user-row"]')[i]!.find<HTMLInputElement>('input[type=checkbox]').element
    // Only the imported rows carry an enabled checkbox.
    expect(box(0).disabled).toBe(true) // active
    expect(box(1).disabled).toBe(false) // imported
    expect(box(2).disabled).toBe(false) // imported
    expect(box(3).disabled).toBe(true) // invited
    box(0).click()
    box(3).click()
    await flushPromises()
    expect(box(0).checked).toBe(false)
    expect(box(3).checked).toBe(false)
    expect(q<HTMLButtonElement>('[data-test="activate-selected"]').disabled).toBe(true)
    // Select all checks exactly the imported rows and opens the drawer for both.
    await click('[data-test="select-all"]')
    expect([0, 1, 2, 3].map((i) => box(i).checked)).toEqual([false, true, true, false])
    expect(q<HTMLButtonElement>('[data-test="activate-selected"]').disabled).toBe(false)
    await click('[data-test="activate-selected"]')
    const targets = q('[data-test="activate-targets"]').textContent!
    expect(targets).toContain('cy@corp.test')
    expect(targets).toContain('didi@corp.test')
    await click('[data-test="activate-send"]')
    const call = fetch.mock.calls.find((c) => String(c[0]) === '/api/v1/admin/users/activate')
    expect(body(call)).toEqual({ user_ids: ['u3', 'u4'], role_ids: [] })
    await flushPromises()
    expect(q('[data-test="activate-summary"]').textContent).toBe('Activation finished: 2 invited, 0 failed.')
    w.unmount()
  })

  it('reports per-user failures without affecting the others and reloads the list', async () => {
    const fetch = stubFetch((url, init) => {
      if (String(url) === '/api/v1/admin/users/activate' && init?.method === 'POST')
        return {
          status: 200,
          body: {
            items: [
              { user_id: 'u3', outcome: 'invited', invitation_id: 'inv-1', reason: null },
              { user_id: 'u4', outcome: 'failed', invitation_id: null, reason: 'not_found' },
            ],
          },
        }
      if (String(url).startsWith('/api/v1/admin/users')) return { status: 200, body: { items: [cy, didi] } }
      if (String(url).startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      if (String(url).startsWith('/api/v1/admin/groups')) return { status: 200, body: { items: [group] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Users)
    await flushPromises()
    await click('[data-test="select-all"]')
    await click('[data-test="activate-selected"]')
    await click('[data-test="activate-send"]')
    await flushPromises()
    expect(q('[data-test="activate-summary"]').textContent).toBe('Activation finished: 1 invited, 1 failed.')
    expect([...document.querySelectorAll('[data-test="activate-failure"]')].map((i) => i.textContent)).toEqual(['didi@corp.test: That record does not exist in your organisation.'])
    expect(listGets(fetch)).toBe(2)
    w.unmount()
  })

  it('shows the self_escalation message when the activation is refused as a whole', async () => {
    stubFetch((url, init) => {
      if (String(url) === '/api/v1/admin/users/activate' && init?.method === 'POST') return { status: 403, body: { reason: 'self_escalation' } }
      if (String(url).startsWith('/api/v1/admin/users')) return { status: 200, body: { items: [cy] } }
      if (String(url).startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      if (String(url).startsWith('/api/v1/admin/groups')) return { status: 200, body: { items: [group] } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Users)
    await flushPromises()
    await click('[data-test="activate"]')
    await pick('activate-roles', 0) // the owner role, beyond an admin's authority
    await click('[data-test="activate-send"]')
    await flushPromises()
    expect(q('[data-test="activate-drawer"] [role=alert]').textContent).toBe('You can only grant permissions you hold yourself.')
    expect(q('[data-test="activate-summary"]')).toBeNull()
    w.unmount()
  })

  it('confirms before removing an imported user and never sends e-mail', async () => {
    let items = [ada, cy]
    const fetch = stubFetch((url, init) => {
      const u = String(url)
      if (u.endsWith('/remove-imported') && init?.method === 'POST') {
        items = items.filter((x) => x.id !== u.split('/')[5])
        return { status: 204, body: null }
      }
      if (u.startsWith('/api/v1/admin/users')) return { status: 200, body: { items } }
      if (u.startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Users)
    await flushPromises()
    await click('[data-test="remove-imported"]')
    const dialog = () => [...document.querySelectorAll('[role=dialog] button')] as HTMLButtonElement[]
    // Cancelling posts nothing; confirming posts to remove-imported and reloads.
    dialog().find((b) => b.textContent?.trim() === 'Cancel')!.click()
    await flushPromises()
    expect(fetch.mock.calls.some((c) => String(c[0]).endsWith('/remove-imported'))).toBe(false)
    await click('[data-test="remove-imported"]')
    dialog().find((b) => b.textContent?.trim() === 'Remove')!.click()
    await flushPromises()
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/users/u3/remove-imported', expect.objectContaining({ method: 'POST' }))
    expect(listGets(fetch)).toBe(2)
    expect(w.findAll('[data-test="user-row"]').length).toBe(1)
    w.unmount()
  })

  it('maps the remove refusal to a message without a reload', async () => {
    const fetch = stubFetch((url, init) => {
      if (String(url).endsWith('/remove-imported') && init?.method === 'POST') return { status: 409, body: { reason: 'invalid_state' } }
      if (String(url).startsWith('/api/v1/admin/users')) return { status: 200, body: { items: [cy] } }
      if (String(url).startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Users)
    await flushPromises()
    await click('[data-test="remove-imported"]')
    ;([...document.querySelectorAll('[role=dialog] button')] as HTMLButtonElement[]).find((b) => b.textContent?.trim() === 'Remove')!.click()
    await flushPromises()
    expect(q('[data-test="error"]').textContent).toBe('That operation is not possible in the current state.')
    expect(listGets(fetch)).toBe(1)
    w.unmount()
  })

  it('resends the invitation for an invited user carrying an invitation_id', async () => {
    const fetch = stubFetch((url) => {
      if (String(url).startsWith('/api/v1/admin/users')) return { status: 200, body: { items: [eli] } }
      if (String(url).startsWith('/api/v1/admin/roles')) return { status: 200, body: roles }
      if (String(url).startsWith('/api/v1/admin/invitations')) return { status: 202, body: { queued: true } }
      return { status: 404, body: { reason: 'not_found' } }
    })
    const w = mountView(Users)
    await flushPromises()
    await click('[data-test="resend"]')
    expect(fetch).toHaveBeenCalledWith('/api/v1/admin/invitations/inv-9/resend', expect.objectContaining({ method: 'POST' }))
    expect(w.findAll('[role=status]').map((t) => t.text()).join(' ')).toContain('eli@x.test')
    w.unmount()
  })
})
