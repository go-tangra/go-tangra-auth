import path from 'node:path'
import { fileURLToPath } from 'node:url'
import { expect, test } from '@playwright/test'
import { expectAccessible, signIn } from './helpers'

// Feature 004: own profile and avatar (quickstart §3).
test.describe('profile', () => {
  test('edit names and phone, upload and remove an avatar', async ({ page }) => {
    await signIn(page)
    await expect(page.getByTestId('roles')).toBeVisible() // signed in (console home)
    await page.goto('/console/security')
    await expect(page.getByTestId('profile-card')).toBeVisible()
    await expectAccessible(page)
    const stamp = String(Date.now()).slice(-5)
    await page.getByTestId('first-name').locator('input').fill('Dana')
    await page.getByTestId('last-name').locator('input').fill(`Kovač ${stamp}`)
    await page.getByTestId('phone').locator('input').fill('+385 91 123 4567')
    await page.getByTestId('profile-save').click()
    await expect(page.getByTestId('profile-saved')).toBeVisible()
    await page.reload()
    await expect(page.getByTestId('phone').locator('input')).toHaveValue('+385911234567')
    // Upload the PNG fixture; the preview shows a picture; remove restores the initials.
    await page.getByTestId('avatar-file').setInputFiles(path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../../../tests/fuzz/testdata/avatars/valid.png'))
    await expect(page.getByTestId('avatar-preview').locator('img')).toBeVisible()
    await page.reload()
    await expect(page.getByTestId('avatar-preview').locator('img')).toBeVisible()
    await page.getByTestId('avatar-remove').click()
    await expect(page.getByTestId('avatar-preview').locator('img')).toHaveCount(0)
    // A disguised file is refused with a clear reason.
    await page.getByTestId('avatar-file').setInputFiles({ name: 'evil.png', mimeType: 'image/png', buffer: Buffer.from('<html><script>alert(1)</script></html>') })
    await expect(page.getByTestId('avatar-error')).toContainText(/PNG, JPEG or WebP|could not be read/)
  })
})
