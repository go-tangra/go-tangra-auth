<script setup lang="ts">
import { computed, nextTick } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { UiCard, UiForm, UiSecretField, UiButton, UiAlert } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api } from '@/api/client'
import { resetSchema } from '@/schemas'
import { summary } from '@/password/rules'
import { usePasswordPolicy } from '@/composables/usePasswordPolicy'
import PasswordRequirements from '@/components/PasswordRequirements.vue'

const route = useRoute()
const router = useRouter()
const token = computed(() => (typeof route.query.token === 'string' ? route.query.token : ''))
const form = useZodForm(resetSchema(() => policy.requirements.value), {
  initial: { password: '', confirm: '' },
  onSubmit: async (v) => {
    let refusal: string | undefined
    try {
      await api('POST', '/api/v1/recovery/complete', { token: token.value, new_password: v.password })
      await router.replace({ name: 'signin' })
    } catch (err) {
      refusal = policy.refusal(err)
      if (refusal === undefined) throw err
    } finally {
      form.values.password = ''
      form.values.confirm = ''
    }
    if (refusal === undefined) return
    // After the cleared fields revalidate, name the rule the server refused.
    await nextTick()
    form.setFieldError('password', refusal)
  },
})
const policy = usePasswordPolicy(
  () => (token.value ? api('POST', '/api/v1/recovery/password-policy', { token: token.value }) : Promise.resolve(undefined)),
  () => String(form.values.password ?? ''),
  () => String(form.values.confirm ?? ''),
)
</script>

<template>
  <UiCard data-test="reset">
    <h1 class="mb-2 text-xl font-semibold">Choose a new password</h1>
    <UiAlert v-if="!token" kind="warning" data-test="no-token">This reset link is incomplete. Request a new one.</UiAlert>
    <UiAlert v-else-if="policy.invalidToken.value" kind="warning" data-test="invalid-token">This reset link is invalid or has expired. Request a new one.</UiAlert>
    <UiForm v-else :form="form">
      <div class="flex flex-col gap-3">
        <UiSecretField v-bind="form.field('password')" label="New password" autocomplete="new-password" :hint="summary(policy.requirements.value)" required data-test="password" />
        <UiSecretField v-bind="form.field('confirm')" label="Confirm new password" autocomplete="new-password" required data-test="confirm" />
        <PasswordRequirements id="reset-pw-rules" :checklist="policy.rules.value" :refused="policy.refused.value" />
        <UiButton type="submit" block :disabled="!policy.satisfied.value" :loading="form.submitting.value" data-test="submit">Set password</UiButton>
      </div>
    </UiForm>
  </UiCard>
</template>
