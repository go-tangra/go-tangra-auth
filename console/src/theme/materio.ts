import type { ThemeDefinition, VuetifyOptions } from 'vuetify'

// Copy of services/gateway/shell/src/theme/materio.ts: the console is served on
// its own before sign-in, so it carries the shell's tokens itself (same
// localStorage key, so the viewer's theme choice follows them across).
// Design tokens of the Materio admin template (themeselection/materio-bootstrap-html-admin-template-free,
// assets/vendor/css/core.css): a #2e263d base colour drawn at 90 % for headings, 70 % for body text
// and 40 % for secondary text, a 12 % border, purple #8c57ff primary and a #f4f5fa page behind white cards.
const palette = {
  primary: '#8c57ff',
  secondary: '#8a8d93',
  success: '#56ca00',
  info: '#16b1ff',
  warning: '#ffb400',
  error: '#ff4c51',
  'on-primary': '#ffffff',
  'on-secondary': '#ffffff',
  'on-success': '#ffffff',
  'on-info': '#ffffff',
  'on-warning': '#ffffff',
  'on-error': '#ffffff',
}

const emphasis = {
  'high-emphasis-opacity': 0.9,
  'medium-emphasis-opacity': 0.7,
  'disabled-opacity': 0.4,
  'border-opacity': 0.12,
  'hover-opacity': 0.06,
  'focus-opacity': 0.1,
  'selected-opacity': 0.08,
  'activated-opacity': 0.12,
  'pressed-opacity': 0.14,
}

export const light: ThemeDefinition = {
  dark: false,
  colors: {
    ...palette,
    background: '#f4f5fa',
    surface: '#ffffff',
    'surface-bright': '#ffffff',
    'surface-light': '#f4f5fa',
    'surface-variant': '#433c50',
    'on-surface-variant': '#f4f5fa',
    'on-background': '#2e263d',
    'on-surface': '#2e263d',
  },
  variables: { ...emphasis, 'border-color': '#2e263d', 'theme-kbd': '#eeeef0', 'theme-on-kbd': '#2e263d', 'theme-code': '#f2f2f3', 'theme-on-code': '#2e263d' },
}

// Materio's dark surfaces (the free template ships light only; these are the
// palette's dark counterparts: #28243d page, #312d4b paper, #e7e3fc base colour).
export const dark: ThemeDefinition = {
  dark: true,
  colors: {
    ...palette,
    background: '#28243d',
    surface: '#312d4b',
    'surface-bright': '#3d3759',
    'surface-light': '#28243d',
    'surface-variant': '#e7e3fc',
    'on-surface-variant': '#28243d',
    'on-background': '#e7e3fc',
    'on-surface': '#e7e3fc',
  },
  variables: { ...emphasis, 'border-color': '#e7e3fc', 'theme-kbd': '#3d3759', 'theme-on-kbd': '#e7e3fc', 'theme-code': '#3d3759', 'theme-on-code': '#e7e3fc' },
}

export type ThemeName = 'light' | 'dark'

/** Vuetify options: the Materio palette with rounded, low-elevation component defaults. */
export function materioTheme(defaultTheme: ThemeName, cspNonce?: string): VuetifyOptions {
  return {
    theme: { defaultTheme, themes: { light, dark }, ...(cspNonce ? { cspNonce } : {}) },
    defaults: {
      VCard: { elevation: 0, rounded: 'lg' },
      VBtn: { rounded: 'lg' },
      VTextField: { variant: 'outlined', density: 'comfortable', color: 'primary' },
      VTextarea: { variant: 'outlined', density: 'comfortable', color: 'primary' },
      VSelect: { variant: 'outlined', density: 'comfortable', color: 'primary' },
      VAutocomplete: { variant: 'outlined', density: 'comfortable', color: 'primary' },
      VCombobox: { variant: 'outlined', density: 'comfortable', color: 'primary' },
      VChip: { rounded: 'sm' },
      VAlert: { variant: 'tonal' },
    },
  }
}

const themeKey = 'freya.theme'

/** The theme the viewer picked earlier; unset when nothing was stored or storage is unavailable. */
export function storedTheme(): ThemeName | undefined {
  try {
    const v = localStorage.getItem(themeKey)
    return v === 'dark' || v === 'light' ? v : undefined
  } catch {
    return undefined
  }
}

export function storeTheme(name: ThemeName): void {
  try {
    localStorage.setItem(themeKey, name)
  } catch {
    // Private windows and blocked storage keep the choice for the tab only.
  }
}
