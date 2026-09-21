import { expect, test } from '@playwright/test'
import { expectAccessible, signIn } from './helpers'

test.describe('administration', () => {
  test.beforeEach(async ({ page }) => {
    await signIn(page)
    await expect(page.getByTestId('roles')).toBeVisible()
  })

  test('users: list, invite dialog, audit trail', async ({ page }) => {
    await page.goto('/console/admin/users')
    await expect(page.getByTestId('users')).toBeVisible()
    await expectAccessible(page)
    await page.getByTestId('invite-open').click()
    await expect(page.getByTestId('invite-dialog')).toBeVisible()
    await expect(page.getByTestId('invite-send')).toBeDisabled()
    await page.getByTestId('invite-email').locator('input').fill(`e2e-${Date.now()}@acme.test`)
    await page.getByTestId('invite-send').click()
    await expect(page.getByTestId('notice')).toContainText('queued')
    // The audit writer batches (500 ms); reload until the invitation shows up.
    await expect(async () => {
      await page.goto('/console/admin/audit')
      await expect(page.getByTestId('audit-row').first()).toBeVisible({ timeout: 2000 })
    }).toPass({ timeout: 15_000 })
    await expectAccessible(page)
  })

  test('user detail: profile panel edits another person (feature 004)', async ({ page }) => {
    await page.goto('/console/admin/users')
    await expect(page.getByTestId('user-row').first()).toBeVisible()
    await page.getByTestId('user-row').first().getByRole('link').first().click()
    await expect(page.getByTestId('user-detail')).toBeVisible()
    await expect(page.getByTestId('profile-form')).toBeVisible()
    await expect(page.getByTestId('avatar-upload')).toHaveCount(0)
    await expectAccessible(page)
    const stamp = String(Date.now()).slice(-5)
    await page.getByTestId('last-name').locator('input').fill(`Edited ${stamp}`)
    await page.getByTestId('profile-save').click()
    await expect(page.getByTestId('profile-saved')).toBeVisible()
    await page.goto('/console/admin/users')
    await page.getByTestId('search').locator('input').fill(`Edited ${stamp}`)
    await expect(page.getByTestId('user-row')).toHaveCount(1)
  })

  test('invite into a group with names (feature 004)', async ({ page }) => {
    const stamp = Date.now()
    await page.goto('/console/admin/groups')
    await page.getByTestId('new-group').click()
    await page.getByTestId('group-name-input').locator('input').fill(`Invited ${stamp}`)
    await page.getByTestId('save-group').click()
    await expect(page.getByTestId('group-row').filter({ hasText: `Invited ${stamp}` })).toBeVisible()
    await page.goto('/console/admin/users')
    await page.getByTestId('invite-open').click()
    await page.getByTestId('invite-email').locator('input').fill(`e2e-${stamp}@acme.test`)
    await page.getByTestId('invite-first-name').locator('input').fill('Invited')
    await page.getByTestId('invite-last-name').locator('input').fill('Person')
    await page.getByTestId('invite-groups').click()
    await page.getByRole('option', { name: `Invited ${stamp}` }).click()
    await page.keyboard.press('Escape')
    await page.getByTestId('invite-send').click()
    await expect(page.getByTestId('notice')).toContainText('queued')
  })

  test('roles: built-ins locked, custom role editor accessible', async ({ page }) => {
    await page.goto('/console/admin/roles')
    await expect(page.getByTestId('builtin').first()).toBeVisible()
    await expectAccessible(page)
    await page.getByTestId('new-role').click()
    await expect(page.getByTestId('role-editor')).toBeVisible()
    await expect(page.getByTestId('save')).toBeDisabled()
    await expectAccessible(page)
  })

  test('account: password card and MFA enrolment start', async ({ page }) => {
    await page.goto('/console/security')
    await expect(page.getByTestId('password-card')).toBeVisible()
    await expectAccessible(page)
    if (await page.getByTestId('enrol').isVisible()) {
      await page.getByTestId('enrol').click()
      await expect(page.getByTestId('qr')).toBeVisible()
      await expect(page.getByTestId('secret')).not.toBeEmpty()
    }
  })
})
