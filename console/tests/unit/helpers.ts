import { vi } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import type { Component } from 'vue'
import { UiToast, UiConfirm } from '@go-tangra/ui'
import { router } from '@/router'

export type Reply = { status: number; body: unknown }
export type Handler = (url: string, init?: RequestInit) => Reply

/** A fetch stub that answers from a handler; 204 bodies are empty. */
export function stubFetch(handler: Handler) {
  const fn = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
    const { status, body } = handler(String(input), init)
    return new Response(status === 204 ? null : JSON.stringify(body), { status, headers: { 'Content-Type': 'application/json' } })
  })
  vi.stubGlobal('fetch', fn)
  return fn
}

/** Mounts a view on the console router with the toast + confirm hosts attached. */
export function mountView(view: Component, props: Record<string, unknown> = {}) {
  return mount(
    {
      components: { View: view, UiToast, UiConfirm },
      props: ['p'],
      template: '<div><View v-bind="p" /><UiToast /><UiConfirm /></div>',
    },
    { props: { p: props }, global: { plugins: [router] }, attachTo: document.body },
  )
}

export const q = <T extends Element = HTMLElement>(sel: string) => document.querySelector(sel) as T
export async function type(sel: string, v: string): Promise<void> {
  const el = q<HTMLInputElement | HTMLTextAreaElement>(sel)
  el.value = v
  el.dispatchEvent(new Event('input'))
  await flushPromises()
}
export async function click(sel: string): Promise<void> {
  q<HTMLButtonElement>(sel).click()
  await flushPromises()
}
export const body = (call: unknown[] | undefined) => JSON.parse(String((call?.[1] as RequestInit).body))
