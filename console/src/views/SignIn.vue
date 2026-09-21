<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, ApiError } from '@/api/client'
import { safeNext, useSignin, type SignInResponse } from '@/stores/signin'

const route = useRoute()
const router = useRouter()
const signin = useSignin()

const tenant = ref(typeof route.query.tenant === 'string' ? route.query.tenant : '')
const email = ref('')
const password = ref('')
const tenantName = ref<string | null>(null)
const error = ref<string | null>(null)
const busy = ref(false)

const slugOk = computed(() => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(tenant.value))
const canSubmit = computed(() => slugOk.value && /^[^\s@]+@[^\s@]+$/.test(email.value) && password.value.length > 0 && !busy.value)

async function resolveTenant(): Promise<void> {
  tenantName.value = null
  if (!slugOk.value) return
  try {
    const t = await api<{ display_name: string }>('GET', '/api/v1/tenants/resolve', undefined, { query: { slug: tenant.value } })
    tenantName.value = t.display_name
  } catch (err) {
    if (!(err instanceof ApiError)) throw err
  }
}

async function submit(): Promise<void> {
  if (!canSubmit.value) return
  error.value = null
  busy.value = true
  try {
    const res = await api<SignInResponse>('POST', '/api/v1/signin', { tenant: tenant.value, email: email.value, password: password.value })
    signin.next = safeNext(route.query.next)
    if (res.mfa_required && res.challenge) {
      signin.challenge = res.challenge
      await router.push({ name: 'signin-mfa' })
      return
    }
    await signin.finish(res, (to) => router.push(to))
  } catch (err) {
    error.value = signin.messageFor(err)
  } finally {
    password.value = ''
    busy.value = false
  }
}
</script>

<template>
  <v-card class="pa-6 pa-sm-8" data-test="signin">
    <div class="brand mb-6" aria-hidden="true">
      <span class="brand__mark"><v-icon icon="mdi-shield-half-full" size="20" /></span>
      <span class="brand__text">Freya</span>
    </div>
    <v-card-title class="text-h4 pa-0 mb-1">Welcome to Freya! 👋</v-card-title>
    <p class="mb-6">Sign in to your organisation to continue.</p>
    <v-form @submit.prevent="submit">
      <v-text-field
        v-model.trim="tenant"
        label="Organisation"
        autocomplete="organization"
        data-test="tenant"
        :hint="tenantName ?? undefined"
        persistent-hint
        class="mb-2"
        @blur="resolveTenant"
      />
      <v-text-field v-model.trim="email" label="Email" type="email" autocomplete="username" data-test="email" class="mb-2" />
      <v-text-field v-model="password" label="Password" type="password" autocomplete="current-password" data-test="password" />
      <div class="d-flex justify-end mb-4">
        <router-link :to="{ name: 'forgot' }" class="text-primary text-body-2 text-decoration-none" data-test="forgot">Forgot your password?</router-link>
      </div>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-4" role="alert" data-test="error">{{ error }}</v-alert>
      <v-btn type="submit" color="primary" size="large" block :disabled="!canSubmit" :loading="busy" data-test="submit">Sign in</v-btn>
    </v-form>
  </v-card>
</template>

<style scoped>
.brand {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}
.brand__mark {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 2rem;
  height: 2rem;
  border-radius: var(--freya-radius);
  background: rgb(var(--v-theme-primary));
  color: rgb(var(--v-theme-on-primary));
  box-shadow: var(--freya-shadow-sm);
}
.brand__text {
  font-size: 1.375rem;
  font-weight: 700;
  letter-spacing: -0.01em;
  color: color-mix(in srgb, rgb(var(--v-theme-on-surface)) calc(var(--v-high-emphasis-opacity) * 100%), transparent);
}
</style>
