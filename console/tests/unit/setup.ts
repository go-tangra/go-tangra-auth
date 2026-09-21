// jsdom lacks a few browser APIs Vuetify components touch on mount.
class RO {
  observe(): void {}
  unobserve(): void {}
  disconnect(): void {}
}
globalThis.ResizeObserver = RO as unknown as typeof ResizeObserver
if (!window.matchMedia) {
  window.matchMedia = (query: string): MediaQueryList =>
    ({ matches: false, media: query, onchange: null, addListener() {}, removeListener() {}, addEventListener() {}, removeEventListener() {}, dispatchEvent: () => false }) as MediaQueryList
}
if (!('visualViewport' in window)) Object.defineProperty(window, 'visualViewport', { value: null })
