import { expect, test } from '@playwright/test'
import { env, expectAccessible, signIn } from './helpers'

test.describe('sign-in', () => {
  test('is accessible and signs a user in within the SC-001 budget', async ({ page }) => {
    await page.goto('/console/signin')
    await expectAccessible(page)
    const started = Date.now()
    await signIn(page)
    await expect(page.getByTestId('roles')).toBeVisible({ timeout: 10_000 })
    expect(Date.now() - started).toBeLessThan(5_000)
    await expectAccessible(page)
  })

  test('never distinguishes wrong password from unknown account', async ({ page }) => {
    await signIn(page, env.tenant, env.email, 'definitely-wrong')
    const first = await page.getByTestId('error').textContent()
    await signIn(page, env.tenant, 'nobody@' + env.tenant + '.test', env.password)
    await expect(page.getByTestId('error')).toHaveText(first ?? '')
  })

  test('serves a strict CSP and security headers on every console route', async ({ request }) => {
    for (const path of ['/console/signin', '/console/', '/api/v1/session']) {
      const res = await request.get(path)
      const csp = res.headers()['content-security-policy'] ?? ''
      expect(csp).toContain("default-src 'self'")
      expect(csp).not.toContain('unsafe-inline')
      expect(res.headers()['strict-transport-security']).toBeTruthy()
      expect(res.headers()['x-content-type-options']).toBe('nosniff')
    }
  })
})
