import { expect, test } from '@playwright/test'
import { env, expectAccessible, signIn } from './helpers'

test.describe('operator', () => {
  test.skip(!env.operatorTotp, 'set E2E_OPERATOR_TOTP with a current code for the operator account')

  test('tenant list and grant dialog are accessible; tenant admins are refused', async ({ page }) => {
    await signIn(page, 'platform', env.operatorEmail, env.operatorPassword)
    await page.getByTestId('code').locator('input').fill(env.operatorTotp ?? '')
    await page.getByTestId('submit').click()
    await page.goto('/console/operator/tenants')
    await expect(page.getByTestId('tenants')).toBeVisible()
    await expectAccessible(page)
    await page.getByTestId('tenant-row').first().locator('a').click()
    await expect(page.getByTestId('tenant-detail')).toBeVisible()
    await page.getByTestId('grant-open').click()
    await page.getByTestId('grant-dialog').getByRole('button', { name: 'Create grant' }).click()
    await expect(page.getByTestId('grant-dialog').getByRole('alert')).toBeVisible() // zod: reason too short
    await expectAccessible(page)
  })

  test('a tenant owner cannot open operator screens', async ({ page }) => {
    await signIn(page)
    await page.goto('/console/operator/tenants')
    await expect(page).toHaveURL(/forbidden/)
  })
})
