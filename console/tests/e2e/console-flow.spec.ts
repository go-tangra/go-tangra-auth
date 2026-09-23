import { expect, test, type Page } from '@playwright/test'
import { env, expectAccessible, signIn } from './helpers'

// T061: the console on the kit at the three reference widths — sign-in
// refusal wording, users → invite (zod refusal first), roles, groups, account,
// no CSP violations, no inline styles, axe clean. Needs a running stack with
// an owner account (E2E_TENANT / E2E_EMAIL / E2E_PASSWORD).
const viewports = [
  { name: 'phone', width: 320, height: 640 },
  { name: 'tablet', width: 768, height: 1024 },
  { name: 'desktop', width: 1280, height: 800 },
]

function watchCsp(page: Page): string[] {
  const violations: string[] = []
  void page.addInitScript(() => {
    document.addEventListener('securitypolicyviolation', (e) => console.error('CSP:' + (e as SecurityPolicyViolationEvent).violatedDirective))
  })
  page.on('console', (m) => { if (m.text().startsWith('CSP:')) violations.push(m.text()) })
  return violations
}

async function openNav(page: Page, key: string): Promise<void> {
  const burger = page.getByRole('button', { name: 'Open navigation' })
  if (await burger.isVisible()) await burger.click()
  await page.getByTestId('nav-' + key).click()
}

test.describe('console on the kit', () => {
  test.skip(!process.env.E2E_PASSWORD, 'E2E_PASSWORD not set')

  for (const vp of viewports) {
    test(`${vp.name}: sign-in refusal → users → invite → roles → groups → account`, async ({ page }) => {
      await page.setViewportSize({ width: vp.width, height: vp.height })
      const violations = watchCsp(page)
      // One generic refusal for a wrong password; the field is cleared.
      await signIn(page, env.tenant, env.email, 'definitely-wrong')
      await expect(page.getByTestId('error')).toBeVisible()
      await expect(page.getByTestId('error')).not.toContainText(/unknown|no account|incorrect/i)
      await expect(page.getByTestId('password').locator('input')).toHaveValue('')
      await signIn(page)
      await expect(page.getByTestId('roles')).toBeVisible({ timeout: 10_000 })
      expect(await page.locator('[style]').count()).toBe(0)
      await expectAccessible(page)

      await openNav(page, 'users')
      await expect(page.getByTestId('users')).toBeVisible()
      await expect(page.getByTestId('user-row').first()).toBeVisible()
      await page.getByTestId('invite-open').click()
      await page.getByTestId('invite-send').click()
      await expect(page.getByTestId('invite-email').getByRole('alert')).toBeVisible()
      await page.getByTestId('invite-email').locator('input').fill(`e2e-${vp.name}-${Date.now()}@acme.test`)
      await page.getByTestId('invite-send').click()
      await expect(page.getByRole('status').filter({ hasText: 'queued' })).toBeVisible()
      await expectAccessible(page)

      await openNav(page, 'roles')
      await expect(page.getByTestId('builtin').first()).toBeVisible()
      await page.getByTestId('new-role').click()
      await page.getByTestId('slug').locator('input').fill('Owner')
      await page.getByTestId('save').click()
      await expect(page.getByTestId('slug').getByRole('alert')).toBeVisible()

      await openNav(page, 'groups')
      await expect(page.getByTestId('groups')).toBeVisible()
      await page.getByTestId('new-group').click()
      await page.getByTestId('group-dialog').getByRole('button', { name: 'Save' }).click()
      await expect(page.getByTestId('group-dialog').getByRole('alert')).toBeVisible()
      await page.keyboard.press('Escape')

      await openNav(page, 'security')
      await expect(page.getByTestId('password-card')).toBeVisible()
      await page.getByTestId('new').locator('input').fill('short')
      await page.getByTestId('pw-submit').click()
      await expect(page.getByTestId('password-card').getByRole('alert').first()).toBeVisible()
      await expectAccessible(page)

      // Theme toggle persists and never inlines styles.
      await page.getByTestId('theme-toggle').click()
      await expect(page.locator('html')).toHaveAttribute('data-theme', /dark|light/)
      expect(await page.locator('[style]').count()).toBe(0)
      expect(violations).toEqual([])
    })
  }
})
