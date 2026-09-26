import { expect, test } from '@playwright/test'
import { expectAccessible, signIn } from './helpers'

// Feature 019 (T068): the role editor groups permissions by module; the same
// action exists under two modules and is granted independently; a module role
// opens read-only and is cloned into an editable custom role.
// `E2E_PLAYWRIGHT=1 go test -tags integration -run TestRolesPlaywright
// ./tests/integration/` starts auth (with warden and ipam registered) plus the
// Vite dev server and runs this file; against another stack set
// AUTH_BASE_URL and E2E_ROLES_* for an owner of a tenant where warden and
// ipam are registered.
const owner = {
  tenant: process.env.E2E_ROLES_TENANT ?? process.env.E2E_TENANT ?? 'acme',
  email: process.env.E2E_ROLES_EMAIL ?? process.env.E2E_EMAIL ?? 'owner@acme.test',
  password: process.env.E2E_ROLES_PASSWORD ?? process.env.E2E_PASSWORD ?? 'owner-password-1',
}

test.describe('module roles', () => {
  test('groups permissions by module and clones a module role', async ({ page }) => {
    await signIn(page, owner.tenant, owner.email, owner.password)
    await expect(page).not.toHaveURL(/\/signin/)

    // New role: one section per module, sorted by display name.
    await page.goto('/console/admin/roles/new')
    const sections = page.getByTestId('module')
    await expect(sections.first()).toBeVisible()
    const titles = await sections.locator('h3').allTextContents()
    expect(titles).toEqual([...titles].sort((a, b) => a.localeCompare(b)))
    const ipam = page.locator('[data-test="module"][data-module="ipam"]')
    const warden = page.locator('[data-test="module"][data-module="warden"]')
    await expect(ipam.locator('h3')).toHaveText('IPAM')
    await expect(warden.locator('h3')).toHaveText('Warden')
    // "backup: manage" under both modules; grant only warden's.
    await expect(ipam.getByText(/^manage/)).toHaveCount(1)
    await warden.getByTestId('group').filter({ hasText: 'backup' }).getByText(/^manage/).click()
    await warden.getByTestId('group').filter({ hasText: 'secrets' }).getByText(/^read/).click()
    await page.getByTestId('slug').locator('input').fill('warden-ops')
    await page.getByTestId('name').locator('input').fill('Warden operations')
    await expectAccessible(page)
    await page.getByTestId('save').click()
    await expect(page).toHaveURL(/\/console\/admin\/roles$/)

    // The list shows the custom role and the module roles with their badge.
    const rows = page.getByTestId('role-row')
    const custom = rows.filter({ hasText: 'warden-ops' })
    await expect(custom.getByTestId('origin')).toHaveText('custom')
    const viewer = rows.filter({ hasText: 'm.warden.viewer' })
    await expect(viewer.getByTestId('origin')).toHaveText('Warden')
    await expect(viewer.getByTestId('edit')).toHaveCount(0)
    await expect(viewer.getByTestId('remove')).toHaveCount(0)

    // The custom role holds exactly warden's backup permission, not ipam's.
    await custom.getByTestId('edit').click()
    await expect(page.locator('[data-test="module"][data-module="warden"] input[type="checkbox"]:checked')).toHaveCount(2)
    await expect(page.locator('[data-test="module"][data-module="ipam"] input[type="checkbox"]:checked')).toHaveCount(0)

    // A module role opens read-only and clones into an editable custom role.
    await page.goto('/console/admin/roles')
    await page.getByTestId('role-row').filter({ hasText: 'm.warden.viewer' }).getByTestId('view').click()
    await expect(page.getByTestId('module-lock')).toBeVisible()
    await expect(page.getByTestId('save')).toBeDisabled()
    await page.getByTestId('clone').first().click()
    const dialog = page.getByTestId('clone-dialog')
    await dialog.getByTestId('clone-name').locator('input').fill('Secret readers')
    await expect(dialog.getByTestId('clone-slug').locator('input')).toHaveValue('secret-readers')
    await dialog.getByTestId('clone-confirm').click()
    await expect(page.getByTestId('module-lock')).toHaveCount(0)
    await expect(page.getByTestId('name').locator('input')).toHaveValue('Secret readers')
    await expect(page.getByTestId('save')).toBeEnabled()
  })
})
