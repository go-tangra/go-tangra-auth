import { expect, test, type CDPSession, type Page } from '@playwright/test'
import { expectAccessible, signIn } from './helpers'

// Feature 018 (T026): register a security key, sign out, sign in with password
// + key and remove the key again, using the Chrome DevTools virtual
// authenticator (WebAuthn.addVirtualAuthenticator). The page must be served
// from the relying party (a host name, not an IP address) over a secure
// context: `go test -tags integration -run TestWebAuthnPlaywright
// ./tests/integration/` starts auth plus the Vite dev server on
// http://localhost and runs this file. Against another stack set
// AUTH_BASE_URL and a dedicated E2E_KEY_* user without a second factor.
const user = {
  tenant: process.env.E2E_KEY_TENANT ?? process.env.E2E_TENANT ?? 'acme',
  email: process.env.E2E_KEY_EMAIL ?? 'keys@acme.test',
  password: process.env.E2E_KEY_PASSWORD ?? 'keys-password-1',
}

async function virtualAuthenticator(page: Page): Promise<{ cdp: CDPSession; id: string }> {
  const cdp = await page.context().newCDPSession(page)
  await cdp.send('WebAuthn.enable')
  const { authenticatorId } = await cdp.send('WebAuthn.addVirtualAuthenticator', {
    options: { protocol: 'ctap2', transport: 'usb', hasResidentKey: false, hasUserVerification: true, isUserVerified: true, automaticPresenceSimulation: true },
  })
  return { cdp, id: authenticatorId }
}

test.describe('security keys', () => {
  test.skip(({ browserName }) => browserName !== 'chromium', 'the virtual authenticator is a Chrome DevTools feature')

  test('registers a key, signs in with it and removes it', async ({ page }) => {
    const { cdp, id } = await virtualAuthenticator(page)

    // Register from the account page; the first factor issues recovery codes.
    await signIn(page, user.tenant, user.email, user.password)
    await expect(page).not.toHaveURL(/\/signin/)
    await page.goto('/console/security')
    const card = page.getByTestId('mfa-card')
    await expect(card.getByTestId('no-keys')).toBeVisible()
    await card.getByTestId('key-name').locator('input').fill('Virtual key')
    await card.getByTestId('add-key').click()
    await expect(page.getByTestId('recovery-codes').locator('li')).toHaveCount(10)
    await page.getByTestId('codes-dismiss').click()
    await expect(page.getByTestId('key-row')).toHaveCount(1)
    await expect(page.getByTestId('key-row')).toContainText('Virtual key')
    await expectAccessible(page)
    const { credentials } = await cdp.send('WebAuthn.getCredentials', { authenticatorId: id })
    expect(credentials).toHaveLength(1)

    // Sign out, then password + key.
    await page.getByTestId('signout').click()
    await expect(page).toHaveURL(/\/signin/)
    await signIn(page, user.tenant, user.email, user.password)
    await expect(page).toHaveURL(/\/signin\/mfa/)
    await expect(page.getByTestId('use-key')).toBeVisible()
    await expectAccessible(page)
    await page.getByTestId('use-key').click()
    await expect(page).not.toHaveURL(/\/signin/)
    const after = await cdp.send('WebAuthn.getCredentials', { authenticatorId: id })
    expect(after.credentials[0]!.signCount).toBeGreaterThan(credentials[0]!.signCount)

    // The key shows its last use; removing it is confirmed with the key itself.
    await page.goto('/console/security')
    const row = page.getByTestId('key-row')
    await expect(row).toContainText('last used')
    await row.getByTestId('remove').click()
    await page.getByTestId('remove-with-key').click()
    await expect(page.getByTestId('no-keys')).toBeVisible()
  })
})
