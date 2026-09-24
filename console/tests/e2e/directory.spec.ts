import { readFileSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { expect, test } from '@playwright/test'
import { expectAccessible, signIn } from './helpers'

// Spec 016 quickstart Scenarios 1–3 in the browser (US1–US3): create a directory
// connection, test it, import a filter-narrowed selection, see the imported users,
// activate one and find the standard invitation in Mailpit. Runs against the dev
// stack with the `ldap` compose profile (T067: repo-owned OpenLDAP seeded from
// services/auth/tests/integration/testdata/openldap/people.ldif, test CA under
// deploy/stack/ldap/) and Mailpit; skips unless the runner exported
// E2E_OPERATOR_PASSWORD, the same "provisioned stack" gate as the other specs.
const ldap = {
  url: process.env.E2E_LDAP_URL ?? 'ldaps://openldap:636',
  bindDN: process.env.E2E_LDAP_BIND_DN ?? 'cn=reader,dc=example,dc=test',
  bindPassword: process.env.E2E_LDAP_BIND_PASSWORD ?? 'reader-password',
  baseDN: process.env.E2E_LDAP_BASE_DN ?? 'ou=Engineering,dc=example,dc=test',
  // The three seeded Engineering people with unique mail. The duplicate-mail
  // twins and the no-mail person stay out of the filter, so the import result
  // is deterministic (see people.ldif for the fixture inventory).
  filter: '(|(uid=eng1)(uid=eng2)(uid=eng5))',
  people: ['eng1@example.test', 'eng2@example.test', 'eng5@example.test'],
  mailpit: process.env.E2E_MAILPIT_URL ?? 'http://127.0.0.1:8025',
}

// The stack's OpenLDAP certificate is signed by the per-stack test CA (quickstart
// Prerequisites), so the connection must pin it. E2E_LDAP_CA_PEM carries the PEM
// itself, E2E_LDAP_CA_FILE an alternate path; by default T067's CA is read.
function caPem(): string {
  if (process.env.E2E_LDAP_CA_PEM) return process.env.E2E_LDAP_CA_PEM
  const path = process.env.E2E_LDAP_CA_FILE
    ?? fileURLToPath(new URL('../../../../../deploy/stack/ldap/ca.pem', import.meta.url))
  return readFileSync(path, 'utf8')
}

test.describe('directory import (LDAP)', () => {
  test.skip(!process.env.E2E_OPERATOR_PASSWORD, 'E2E_OPERATOR_PASSWORD not set: needs the provisioned stack with the ldap profile')

  test.beforeEach(async ({ page }) => {
    await signIn(page)
    await expect(page.getByTestId('roles')).toBeVisible()
  })

  test('connect → test → import a filtered selection → activate → invitation in Mailpit', async ({ page, request }) => {
    test.slow() // sends a real invitation through the outbox relay
    const name = `E2E Directory ${Date.now()}`

    // US1 (quickstart Scenario 1): create the connection and test it before saving.
    await page.goto('/console/admin/directories')
    await expect(page.getByTestId('directories')).toBeVisible()
    await expectAccessible(page)
    await page.getByTestId('new-directory').click()
    const drawer = page.getByTestId('directory-drawer')
    await expect(drawer).toBeVisible()
    await drawer.getByTestId('directory-name').locator('input').fill(name)
    await drawer.getByTestId('directory-kind').locator('select').selectOption('openldap')
    // The OpenLDAP preset fills the attribute mapping (entryUUID / mail / cn / …).
    await expect(drawer.getByTestId('attr-uid').locator('input')).toHaveValue('entryUUID')
    await drawer.getByTestId('directory-url').locator('input').fill(ldap.url)
    await drawer.locator('textarea[data-field="ca_pem"]').fill(caPem())
    await drawer.getByTestId('bind-dn').locator('input').fill(ldap.bindDN)
    await drawer.getByTestId('bind-password').locator('input').fill(ldap.bindPassword)
    await drawer.getByTestId('base-dn').locator('input').fill(ldap.baseDN)
    await drawer.getByTestId('test-connection').click()
    await expect(drawer.getByTestId('test-result')).toContainText('Connection OK')
    await expectAccessible(page)
    await drawer.getByTestId('save-directory').click()
    const connection = page.getByTestId('directory-row').filter({ hasText: name })
    await expect(connection).toBeVisible()
    await expect(connection.getByTestId('directory-url')).toHaveText(ldap.url)

    // US2 (quickstart Scenario 2): filter the directory, import the selection.
    await page.goto('/console/admin/directory-import')
    await expect(page.getByTestId('directory-import')).toBeVisible()
    await page.getByTestId('connection').locator('select').selectOption({ label: name })
    await page.getByTestId('filter').locator('input').fill(ldap.filter)
    await page.getByTestId('search-directory').click()
    await expect(page.getByTestId('preview-row')).toHaveCount(ldap.people.length)
    // Only new or already-imported rows are selectable; that count is what the
    // import must move (created or refreshed), so the suite stays re-runnable.
    const selectable = await page.getByTestId('preview-row').locator('input[type=checkbox]:enabled').count()
    expect(selectable).toBeGreaterThan(0)
    await expectAccessible(page)
    await page.getByTestId('select-all').click()
    await page.getByTestId('import').click()
    const summary = page.getByTestId('import-summary')
    await expect(summary).toBeVisible()
    const text = (await summary.textContent()) ?? ''
    const counts = /(\d+) created, (\d+) updated, (\d+) skipped, (\d+) failed/.exec(text)
    if (!counts) throw new Error(`unexpected import summary: ${text}`)
    expect(Number(counts[1]) + Number(counts[2])).toBe(selectable)
    expect(Number(counts[3])).toBe(0)
    expect(Number(counts[4])).toBe(0)

    // FR-010: the users list shows the imported people with their directory origin.
    await page.goto('/console/admin/users')
    await page.getByTestId('status').locator('select').selectOption('imported')
    for (const email of ldap.people) {
      const row = page.getByTestId('user-row').filter({ hasText: email })
      await expect(row).toBeVisible()
      await expect(row.getByTestId('status-chip')).toHaveText('imported')
      await expect(row.getByTestId('origin')).toContainText(name)
    }
    await expectAccessible(page)

    // US3 (quickstart Scenario 3): activate an imported user (no extra roles).
    const target = page.getByTestId('user-row').filter({ has: page.getByTestId('activate') }).first()
    await expect(target).toBeVisible()
    const email = ((await target.getByRole('link').first().textContent()) ?? '').trim()
    expect(email).toMatch(/@/)
    await target.getByTestId('activate').click()
    const activation = page.getByTestId('activate-drawer')
    await expect(activation).toBeVisible()
    await expect(activation.getByTestId('activate-targets')).toContainText(email)
    await activation.getByTestId('activate-send').click()
    await expect(page.getByTestId('activate-summary')).toContainText('1 invited, 0 failed.')
    // The row is now invited (leave the imported filter to see it).
    await page.getByTestId('status').locator('select').selectOption('')
    const activated = page.getByTestId('user-row').filter({ hasText: email })
    await expect(activated.getByTestId('status-chip')).toHaveText('invited')
    await expect(activated.getByTestId('resend')).toBeVisible()
    await expectAccessible(page)

    // SC-003: the standard invitation reaches Mailpit within the minute.
    const findInvitation = async (): Promise<string | null> => {
      const res = await request.get(`${ldap.mailpit}/api/v1/search`, { params: { query: `to:${email}` } })
      const list = await res.json() as { messages: { ID: string }[] }
      const latest = list.messages[0]
      if (!latest) return null
      const message = await request.get(`${ldap.mailpit}/api/v1/message/${latest.ID}`)
      const body = await message.json() as { Text: string }
      return body.Text
    }
    await expect.poll(async () => (await findInvitation()) !== null, { timeout: 60_000, intervals: [500, 1_000, 2_500] }).toBe(true)
    expect(await findInvitation()).toContain('/console/invite/accept?token=')
  })
})
