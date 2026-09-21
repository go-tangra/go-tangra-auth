import { fileURLToPath, URL } from 'node:url'
import { defineConfig } from 'vitest/config'
import vue from '@vitejs/plugin-vue'
import vuetify from 'vite-plugin-vuetify'
import { federation } from '@module-federation/vite'
import { remoteConfig } from './module-federation.config'

// VITE_REMOTE=1 builds the console as the federated remote `auth` served by the
// auth service under /ui/ and relayed by the gateway at /m/auth/.
const remote = process.env.VITE_REMOTE === '1'

// The console is served by the auth service under /console/; in development
// API calls are proxied to the edge listener (self-signed dev certificate).
export default defineConfig({
  base: remote ? '/m/auth/' : '/console/',
  resolve: { alias: { '@': fileURLToPath(new URL('./src', import.meta.url)) } },
  plugins: [vue(), vuetify({ autoImport: true }), ...(remote ? [federation(remoteConfig)] : [])],
  server: {
    proxy: {
      '/api': { target: 'https://127.0.0.1:8443', secure: false, changeOrigin: false },
      '/.well-known': { target: 'https://127.0.0.1:8443', secure: false },
    },
  },
  build: { outDir: remote ? 'dist-remote' : 'dist', emptyOutDir: true, sourcemap: false, target: 'esnext' },
  test: {
    environment: 'jsdom',
    environmentOptions: { jsdom: { url: 'https://localhost/console/' } },
    include: ['tests/unit/**/*.spec.ts'],
    setupFiles: ['tests/unit/setup.ts'],
    server: { deps: { inline: ['vuetify'] } },
  },
})
