import { expect, test } from '@playwright/test'
import { expectAccessible, signIn } from './helpers'

// Feature 004: groups grant roles; the console manages them (quickstart §2).
test.describe('groups', () => {
  test.beforeEach(async ({ page }) => {
    await signIn(page)
    await expect(page.getByTestId('roles').or(page.getByTestId('nav-home')).first()).toBeVisible()
  })

  test('create a group, grant a role, add a member, see it as a source, delete with confirmation', async ({ page }) => {
    const name = `Finance ${Date.now()}`
    await page.goto('/console/admin/groups')
    await expect(page.getByTestId('groups')).toBeVisible()
    await expectAccessible(page)
    await page.getByTestId('new-group').click()
    await page.getByTestId('group-name-input').locator('input').fill(name)
    await page.getByTestId('save-group').click()
    const row = page.getByTestId('group-row').filter({ hasText: name })
    await expect(row).toBeVisible()
    await row.getByTestId('group-name').click()
    await expect(page.getByTestId('group-detail')).toBeVisible()
    await expectAccessible(page)
    // Grant the first non-owner role.
    await page.getByTestId('group-role').first().locator('input').check()
    await page.getByTestId('save-roles').click()
    await expect(page.getByTestId('notice')).toContainText('Roles updated')
    // Add the signed-in owner as a member (any user of the tenant works).
    await page.getByTestId('add-member').locator('input').fill(process.env.E2E_EMAIL ?? 'owner@acme.test')
    await page.getByRole('option').first().click()
    await page.getByTestId('add-member-confirm').click()
    await expect(page.getByTestId('member-row')).toHaveCount(1)
    // The member's page shows the role "via <group>".
    await page.getByTestId('member-row').getByRole('link').first().click()
    await expect(page.getByTestId('effective-roles')).toContainText(`via ${name}`)
    await expect(page.getByTestId('user-groups')).toContainText(name)
    // Delete with the member count confirmation.
    await page.goto('/console/admin/groups')
    await page.getByTestId('group-row').filter({ hasText: name }).getByTestId('delete-group').click()
    await expect(page.getByTestId('delete-summary')).toContainText('1 member')
    await page.getByTestId('confirm-delete').click()
    await expect(page.getByTestId('group-row').filter({ hasText: name })).toHaveCount(0)
  })
})
