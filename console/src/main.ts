import { createApp } from 'vue'
import { createPinia } from 'pinia'
import { createVuetify } from 'vuetify'
import 'vuetify/styles'
import '@mdi/font/css/materialdesignicons.css' // icon font (mdi-* names), bundled: CSP font-src 'self'
import '@fontsource-variable/inter' // Materio's typeface, bundled for the same reason
import '@/theme/materio.css'
import App from './App.vue'
import { router } from './router'
import { i18n } from './plugins/i18n'
import { materioTheme, storedTheme } from '@/theme/materio'

// The server injects a per-request CSP nonce; Vuetify's runtime styles must
// carry it or the strict style-src policy blocks them. Browsers hide the
// nonce attribute once CSP is active, so it must be read from the property.
const cspNonce = document.querySelector<HTMLMetaElement>('meta[property="csp-nonce"]')?.nonce || undefined
// The shell's Materio theme (src/theme/materio.ts); its 70 % body text is
// #6d6777 on white, 5.4:1, which clears WCAG AA for field labels and hints.
const vuetify = createVuetify(materioTheme(storedTheme() ?? 'light', cspNonce))

createApp(App).use(createPinia()).use(router).use(vuetify).use(i18n).mount('#app')
