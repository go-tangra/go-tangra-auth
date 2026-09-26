import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import tailwindcss from '@tailwindcss/vite'
import { breakpointSpecificity } from '@go-tangra/ui/vite'
import { federation } from '@module-federation/vite'
import { remoteConfig } from './module-federation.config'

// VITE_REMOTE=1 builds the console as the federated remote `auth` served by the
// auth service under /ui/ and relayed by the gateway at /m/auth/.
const remote = process.env.VITE_REMOTE === '1'

// The console is served by the auth service under /console/; in development
// API calls are proxied to the edge listener (self-signed dev certificate),
// AUTH_EDGE_URL overriding the default. The security-key e2e harness serves
// the console on http://localhost (browsers allow WebAuthn there but not on a
// page with certificate errors); the edge only accepts https origins, so with
// AUTH_EDGE_URL set the proxy presents the edge's own origin.
const edge = process.env.AUTH_EDGE_URL ?? 'https://127.0.0.1:8443'
const asEdge = process.env.AUTH_EDGE_URL
  ? { configure: (proxy: { on: (ev: 'proxyReq', fn: (req: { getHeader: (h: string) => unknown; setHeader: (h: string, v: string) => void }) => void) => void }) => proxy.on('proxyReq', (req) => { if (req.getHeader('origin')) req.setHeader('origin', edge) }) }
  : {}
export default defineConfig({
  base: remote ? '/m/auth/' : '/console/',
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  plugins: [vue(), tailwindcss(), breakpointSpecificity(), ...(remote ? [federation(remoteConfig)] : [])],
  server: {
    proxy: {
      '/api': { target: edge, secure: false, changeOrigin: false, ...asEdge },
      '/.well-known': { target: edge, secure: false },
    },
  },
  build: { outDir: remote ? 'dist-remote' : 'dist', emptyOutDir: true, sourcemap: false, target: 'esnext' },
  test: {
    environment: 'jsdom',
    environmentOptions: { jsdom: { url: 'https://localhost/console/' } },
    include: ['tests/unit/**/*.spec.ts'],
    setupFiles: ['tests/unit/setup.ts'],
    server: { deps: { inline: ['@go-tangra/ui'] } },
  },
})
