import { expect, type Page } from '@playwright/test'
import AxeBuilder from '@axe-core/playwright'

/** Credentials come from the environment so the suite runs against any stack. */
export const env = {
  tenant: process.env.E2E_TENANT ?? 'acme',
  email: process.env.E2E_EMAIL ?? 'owner@acme.test',
  password: process.env.E2E_PASSWORD ?? 'owner-password-1',
  operatorEmail: process.env.E2E_OPERATOR_EMAIL ?? 'ops@example.org',
  operatorPassword: process.env.E2E_OPERATOR_PASSWORD ?? 'operator-password-1',
  operatorTotp: process.env.E2E_OPERATOR_TOTP, // 6-digit code supplied by the runner
}

export async function signIn(page: Page, tenant = env.tenant, email = env.email, password = env.password): Promise<void> {
  await page.goto('/console/signin')
  await page.getByTestId('tenant').locator('input').fill(tenant)
  await page.getByTestId('email').locator('input').fill(email)
  await page.getByTestId('password').locator('input').fill(password)
  await page.getByTestId('submit').click()
}

/** SC-009: no serious or critical accessibility violations on the page. */
export async function expectAccessible(page: Page): Promise<void> {
  const results = await new AxeBuilder({ page }).withTags(['wcag2a', 'wcag2aa']).analyze()
  const blocking = results.violations.filter((v) => v.impact === 'serious' || v.impact === 'critical')
  expect(blocking, JSON.stringify(blocking.map((v) => ({ id: v.id, nodes: v.nodes.length })))).toEqual([])
}
