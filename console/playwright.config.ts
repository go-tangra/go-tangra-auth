import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: 'tests/e2e',
  timeout: 60_000,
  use: {
    baseURL: process.env.AUTH_BASE_URL ?? 'https://127.0.0.1:8443',
    ignoreHTTPSErrors: true,
    testIdAttribute: 'data-test',
    // PW_CHANNEL=chrome runs on the system Chrome (no bundled browser download).
    ...(process.env.PW_CHANNEL ? { channel: process.env.PW_CHANNEL } : {}),
  },
  reporter: [['list'], ['html', { open: 'never' }]],
})
