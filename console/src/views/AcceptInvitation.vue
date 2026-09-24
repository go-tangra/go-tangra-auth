<script setup lang="ts">
import { computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { UiCard, UiForm, UiInput, UiSecretField, UiButton, UiAlert } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api } from '@/api/client'
import { useSignin, type SignInResponse } from '@/stores/signin'
import { acceptInvitationSchema } from '@/schemas'

const route = useRoute()
const router = useRouter()
const signin = useSignin()
const token = computed(() => (typeof route.query.token === 'string' ? route.query.token : ''))
const form = useZodForm(acceptInvitationSchema(), {
  initial: { display_name: '', password: '', confirm: '' },
  onSubmit: async (v) => {
    try {
      const res = await api<SignInResponse>('POST', '/api/v1/invitations/accept', { token: token.value, display_name: v.display_name, password: v.password })
      signin.next = '/'
      await signin.finish(res, (to) => router.push(to))
    } finally {
      form.values.password = ''
      form.values.confirm = ''
    }
  },
})
</script>

<template>
  <UiCard data-test="accept">
    <h1 class="mb-2 text-xl font-semibold">Set up your account</h1>
    <UiAlert v-if="!token" kind="warning" data-test="no-token">This invitation link is incomplete. Ask your administrator to send a new one.</UiAlert>
    <UiForm v-else :form="form">
      <div class="flex flex-col gap-3">
        <UiInput v-bind="form.field('display_name')" label="Your name" autocomplete="name" required data-test="name" />
        <UiSecretField v-bind="form.field('password')" label="Password" autocomplete="new-password" hint="At least the organisation minimum length" required data-test="password" />
        <UiSecretField v-bind="form.field('confirm')" label="Confirm password" autocomplete="new-password" required data-test="confirm" />
        <UiButton type="submit" block :loading="form.submitting.value" data-test="submit">Activate account</UiButton>
      </div>
    </UiForm>
  </UiCard>
</template>
