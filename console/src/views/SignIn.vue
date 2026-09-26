<script setup lang="ts">
import { ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { UiCard, UiIcon, UiForm, UiInput, UiSecretField, UiButton, UiAlert } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { safeNext, useSignin, type SignInResponse } from '@/stores/signin'
import { signInSchema } from '@/schemas'

const route = useRoute()
const router = useRouter()
const signin = useSignin()
const tenantName = ref<string | null>(null)
const refusal = ref<string | null>(null)
const passwordEl = ref<HTMLElement | null>(null)

const form = useZodForm(signInSchema, {
  initial: { tenant: typeof route.query.tenant === 'string' ? route.query.tenant : '', email: '', password: '' },
  onSubmit: async (v) => {
    refusal.value = null
    try {
      const res = await api<SignInResponse>('POST', '/api/v1/signin', v)
      signin.next = safeNext(route.query.next)
      if (res.mfa_required && res.challenge) {
        signin.challenge = res.challenge
        signin.methods = res.mfa_methods ?? []
        await router.push({ name: 'signin-mfa' })
        return
      }
      await signin.finish(res, (to) => router.push(to))
    } catch (err) {
      // One shared refusal message (no account enumeration); the password field is cleared and refocused.
      refusal.value = signin.messageFor(err)
      throw err
    } finally {
      form.values.password = ''
      passwordEl.value?.querySelector('input')?.focus()
    }
  },
})
async function resolveTenant(): Promise<void> {
  tenantName.value = null
  const t = signInSchema.shape.tenant.safeParse(form.values.tenant)
  if (!t.success || t.data === '') return
  try {
    tenantName.value = (await api<{ display_name: string }>('GET', '/api/v1/tenants/resolve', undefined, { query: { slug: t.data } })).display_name
  } catch (err) {
    if (!(err instanceof ApiError)) throw err
  }
}
</script>

<template>
  <UiCard data-test="signin">
    <div class="flex items-center gap-3" aria-hidden="true">
      <span class="rounded-field bg-primary text-primary-content flex size-9 items-center justify-center"><UiIcon name="mdi-shield-half-full" /></span>
      <span class="text-base-content text-xl font-bold tracking-tight">Tangra</span>
    </div>
    <div>
      <h1 class="text-base-content mb-1.5 text-2xl font-semibold">Welcome to Tangra! 👋</h1>
      <p class="text-base-content/80">Sign in to your organisation to continue.</p>
    </div>
    <UiForm :form="form">
      <div class="space-y-4">
        <UiInput v-bind="form.field('tenant')" label="Organisation" placeholder="acme" autocomplete="organization" :hint="tenantName ?? 'Optional — leave blank to use your email domain'" data-test="tenant" @blur="form.blur('tenant'); resolveTenant()" />
        <UiInput v-bind="form.field('email')" label="Email" type="email" placeholder="you@example.org" autocomplete="username" required data-test="email" />
        <div ref="passwordEl"><UiSecretField v-bind="form.field('password')" label="Password" placeholder="············" autocomplete="current-password" :revealable="false" required data-test="password" /></div>
        <div class="flex justify-end"><RouterLink :to="{ name: 'forgot' }" class="link link-animated link-primary text-sm font-normal" data-test="forgot">Forgot your password?</RouterLink></div>
        <UiAlert v-if="refusal" kind="error" role="alert" data-test="error">{{ refusal }}</UiAlert>
        <UiButton type="submit" size="lg" block :loading="form.submitting.value" data-test="submit">Sign in</UiButton>
      </div>
    </UiForm>
  </UiCard>
</template>
