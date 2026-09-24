<script setup lang="ts">
import { ref } from 'vue'
import { UiCard, UiForm, UiInput, UiButton, UiAlert } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { api } from '@/api/client'
import { forgotSchema } from '@/schemas'

const sent = ref(false)
const form = useZodForm(forgotSchema, {
  initial: { tenant: '', email: '' },
  onSubmit: async (v) => {
    try {
      await api('POST', '/api/v1/recovery', v)
    } catch {
      // The response is the same whether or not the account exists.
    } finally {
      sent.value = true
    }
  },
})
</script>

<template>
  <UiCard data-test="forgot">
    <h1 class="mb-2 text-xl font-semibold">Reset your password</h1>
    <template v-if="sent">
      <UiAlert kind="info" data-test="sent">If an account exists for that address, a reset link is on its way. It is valid for 30 minutes.</UiAlert>
      <div class="mt-4 text-center"><RouterLink :to="{ name: 'signin' }" class="link link-primary">Back to sign in</RouterLink></div>
    </template>
    <UiForm v-else :form="form">
      <div class="flex flex-col gap-3">
        <UiInput v-bind="form.field('tenant')" label="Organisation" autocomplete="organization" hint="Optional — leave blank to use your email domain" data-test="tenant" />
        <UiInput v-bind="form.field('email')" label="Email" type="email" autocomplete="username" required data-test="email" />
        <UiButton type="submit" block :loading="form.submitting.value" data-test="submit">Send reset link</UiButton>
      </div>
    </UiForm>
  </UiCard>
</template>
