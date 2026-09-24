<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { UiPage, UiCard, UiAlert, UiButton, UiForm, UiInput, UiNumberInput, UiSwitch } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import type { components } from '@/api/schema'
import { policySchema } from '@/schemas'

type Policy = Required<components['schemas']['Policy']>
const defaults: Policy = { session_lifetime: '8h', idle_timeout: '1h', access_token_lifetime: '15m', password_min_length: 12, mfa_required: false, lockout_threshold: 10, lockout_duration: '15m' }
const loadError = ref<string | null>(null)
const saved = ref(false)
const form = useZodForm(policySchema, {
  initial: defaults,
  onSubmit: async (v) => {
    saved.value = false
    const p = await api<Policy>('PUT', '/api/v1/admin/policy', v)
    form.reset({ ...defaults, ...p })
    saved.value = true
  },
})
async function load(): Promise<void> {
  try {
    form.reset({ ...defaults, ...(await api<Policy>('GET', '/api/v1/admin/policy')) })
  } catch (err) {
    loadError.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load the policy.'
  }
}
onMounted(load)
</script>

<template>
  <UiPage title="Security policy" data-test="policy">
    <UiCard>
      <UiAlert v-if="loadError" kind="error" class="mb-3" data-test="error">{{ loadError }}</UiAlert>
      <UiForm :form="form">
        <div class="grid grid-cols-1 gap-3 md:grid-cols-3">
          <UiInput v-bind="form.field('session_lifetime')" label="Session lifetime" hint="≤ 24h" required data-test="session_lifetime" />
          <UiInput v-bind="form.field('idle_timeout')" label="Idle timeout" hint="≤ session lifetime" required data-test="idle_timeout" />
          <UiInput v-bind="form.field('access_token_lifetime')" label="Access token lifetime" hint="≤ 15m" required data-test="access_token_lifetime" />
          <UiNumberInput v-bind="form.field('password_min_length')" label="Minimum password length" :min="8" :max="128" required data-test="password_min_length" />
          <UiNumberInput v-bind="form.field('lockout_threshold')" label="Lockout threshold" :min="3" :max="20" required data-test="lockout_threshold" />
          <UiInput v-bind="form.field('lockout_duration')" label="Lockout duration" hint="1m – 1h" required data-test="lockout_duration" />
          <div class="md:col-span-3"><UiSwitch v-bind="form.field('mfa_required')" label="Require a second factor for every user" data-test="mfa_required" /></div>
        </div>
        <UiAlert v-if="saved" kind="success" class="mt-3" data-test="saved">Policy saved. It applies to new sign-ins and decisions immediately.</UiAlert>
        <UiButton type="submit" class="mt-4" :loading="form.submitting.value" data-test="save">Save policy</UiButton>
      </UiForm>
    </UiCard>
  </UiPage>
</template>
