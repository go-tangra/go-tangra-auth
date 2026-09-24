<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { UiCard, UiForm, UiSecretField, UiButton, UiAlert } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api } from '@/api/client'
import { resetSchema } from '@/schemas'

const route = useRoute()
const router = useRouter()
const token = computed(() => (typeof route.query.token === 'string' ? route.query.token : ''))
const form = useZodForm(resetSchema(), {
  initial: { password: '', confirm: '' },
  onSubmit: async (v) => {
    try {
      await api('POST', '/api/v1/recovery/complete', { token: token.value, new_password: v.password })
      await router.replace({ name: 'signin' })
    } finally {
      form.values.password = ''
      form.values.confirm = ''
    }
  },
})
</script>

<template>
  <UiCard data-test="reset">
    <h1 class="mb-2 text-xl font-semibold">Choose a new password</h1>
    <UiAlert v-if="!token" kind="warning" data-test="no-token">This reset link is incomplete. Request a new one.</UiAlert>
    <UiForm v-else :form="form">
      <div class="flex flex-col gap-3">
        <UiSecretField v-bind="form.field('password')" label="New password" autocomplete="new-password" required data-test="password" />
        <UiSecretField v-bind="form.field('confirm')" label="Confirm new password" autocomplete="new-password" required data-test="confirm" />
        <UiButton type="submit" block :loading="form.submitting.value" data-test="submit">Set password</UiButton>
      </div>
    </UiForm>
  </UiCard>
</template>
