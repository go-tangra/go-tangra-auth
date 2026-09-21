<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'

const route = useRoute()
const router = useRouter()
const token = computed(() => (typeof route.query.token === 'string' ? route.query.token : ''))
const password = ref('')
const confirm = ref('')
const error = ref<string | null>(null)
const busy = ref(false)
const canSubmit = computed(() => token.value !== '' && password.value.length >= 8 && password.value === confirm.value && !busy.value)

async function submit(): Promise<void> {
  if (!canSubmit.value) return
  busy.value = true
  error.value = null
  try {
    await api('POST', '/api/v1/recovery/complete', { token: token.value, new_password: password.value })
    await router.replace({ name: 'signin' })
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not reset the password.'
  } finally {
    busy.value = false
    password.value = ''
    confirm.value = ''
  }
}
</script>

<template>
  <v-card class="pa-6" data-test="reset">
    <v-card-title class="text-h5 mb-2">Choose a new password</v-card-title>
    <v-alert v-if="!token" type="warning" variant="tonal" data-test="no-token">This reset link is incomplete. Request a new one.</v-alert>
    <v-form v-else @submit.prevent="submit">
      <v-text-field v-model="password" label="New password" type="password" autocomplete="new-password" data-test="password" />
      <v-text-field v-model="confirm" label="Confirm new password" type="password" autocomplete="new-password" data-test="confirm" />
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-4" role="alert" data-test="error">{{ error }}</v-alert>
      <v-btn type="submit" color="primary" block :disabled="!canSubmit" :loading="busy" data-test="submit">Set password</v-btn>
    </v-form>
  </v-card>
</template>
