<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useSignin, type SignInResponse } from '@/stores/signin'

const route = useRoute()
const router = useRouter()
const signin = useSignin()
const token = computed(() => (typeof route.query.token === 'string' ? route.query.token : ''))
const name = ref('')
const password = ref('')
const confirm = ref('')
const error = ref<string | null>(null)
const busy = ref(false)
const canSubmit = computed(() => token.value !== '' && name.value.trim().length > 0 && password.value.length >= 8 && password.value === confirm.value && !busy.value)

async function submit(): Promise<void> {
  if (!canSubmit.value) return
  busy.value = true
  error.value = null
  try {
    const res = await api<SignInResponse>('POST', '/api/v1/invitations/accept', { token: token.value, display_name: name.value.trim(), password: password.value })
    signin.next = '/'
    await signin.finish(res, (to) => router.push(to))
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not accept the invitation.'
  } finally {
    busy.value = false
    password.value = ''
    confirm.value = ''
  }
}
</script>

<template>
  <v-card class="pa-6" data-test="accept">
    <v-card-title class="text-h5 mb-2">Set up your account</v-card-title>
    <v-alert v-if="!token" type="warning" variant="tonal" data-test="no-token">This invitation link is incomplete. Ask your administrator to send a new one.</v-alert>
    <v-form v-else @submit.prevent="submit">
      <v-text-field v-model="name" label="Your name" autocomplete="name" data-test="name" />
      <v-text-field v-model="password" label="Password" type="password" autocomplete="new-password" data-test="password" hint="At least the organisation minimum length" />
      <v-text-field v-model="confirm" label="Confirm password" type="password" autocomplete="new-password" data-test="confirm" />
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-4" role="alert" data-test="error">{{ error }}</v-alert>
      <v-btn type="submit" color="primary" block :disabled="!canSubmit" :loading="busy" data-test="submit">Activate account</v-btn>
    </v-form>
  </v-card>
</template>
