import { inject, type App, type InjectionKey } from 'vue'

// Minimal message catalogue; keys are stable so a full i18n library can be
// dropped in later without touching views.
export const messages = {
  en: {
    'app.title': 'Auth Console',
    'nav.home': 'Home',
    'nav.sessions': 'Sessions',
    'nav.security': 'Security',
    'nav.users': 'Users',
    'nav.groups': 'Groups',
    'nav.roles': 'Roles',
    'nav.policy': 'Policy',
    'nav.audit': 'Audit',
    'nav.clients': 'Applications',
    'nav.tenants': 'Tenants',
    'nav.signout': 'Sign out',
    'outage.title': 'The service is temporarily unavailable',
    'outage.body': 'Please try again in a moment. Nothing you entered has been lost.',
    'outage.retry': 'Retry',
    'forbidden.title': 'You do not have access to this page',
    'notfound.title': 'Page not found',
  },
} as const

export type MessageKey = keyof (typeof messages)['en']

export type Translate = (key: MessageKey, vars?: Record<string, string | number>) => string

export const I18nKey: InjectionKey<Translate> = Symbol('i18n')

export function translate(locale: keyof typeof messages, key: MessageKey, vars?: Record<string, string | number>): string {
  let text: string = messages[locale][key] ?? key
  for (const [k, v] of Object.entries(vars ?? {})) text = text.replaceAll(`{${k}}`, String(v))
  return text
}

export const i18n = {
  install(app: App) {
    const t: Translate = (key, vars) => translate('en', key, vars)
    app.provide(I18nKey, t)
    app.config.globalProperties.$t = t
  },
}

export function useI18n(): { t: Translate } {
  const t = inject(I18nKey, (key: MessageKey) => translate('en', key))
  return { t }
}

declare module 'vue' {
  interface ComponentCustomProperties {
    $t: Translate
  }
}
