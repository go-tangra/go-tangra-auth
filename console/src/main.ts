import { createApp } from 'vue'
import { createPinia } from 'pinia'
import '@fontsource-variable/inter' // bundled typeface (CSP font-src 'self')
import './app.css'
import App from './App.vue'
import { router } from './router'
import { i18n } from './plugins/i18n'

// Standalone console: the kit theme is applied through data-theme on <html>
// (useTheme in the layout); no runtime style injection, so the strict
// style-src policy needs no nonce.
createApp(App).use(createPinia()).use(router).use(i18n).mount('#app')
