<script setup lang="ts">
import { computed, ref } from 'vue'
import { api } from '@/api/client'

const tenant = ref('')
const email = ref('')
const sent = ref(false)
const busy = ref(false)
const canSubmit = computed(() => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(tenant.value) && /^[^\s@]+@[^\s@]+$/.test(email.value) && !busy.value)

async function submit(): Promise<void> {
  if (!canSubmit.value) return
  busy.value = true
  try {
    await api('POST', '/api/v1/recovery', { tenant: tenant.value, email: email.value })
  } catch {
    // The response is the same whether or not the account exists.
  } finally {
    sent.value = true
    busy.value = false
  }
}
</script>

<template>
  <v-card class="pa-6" data-test="forgot">
    <v-card-title class="text-h5 mb-2">Reset your password</v-card-title>
    <template v-if="sent">
      <v-alert type="info" variant="tonal" data-test="sent">If an account exists for that address, a reset link is on its way. It is valid for 30 minutes.</v-alert>
      <div class="mt-4 text-center"><router-link :to="{ name: 'signin' }">Back to sign in</router-link></div>
    </template>
    <v-form v-else @submit.prevent="submit">
      <v-text-field v-model.trim="tenant" label="Organisation" data-test="tenant" />
      <v-text-field v-model.trim="email" label="Email" type="email" data-test="email" />
      <v-btn type="submit" color="primary" block :disabled="!canSubmit" :loading="busy" data-test="submit">Send reset link</v-btn>
    </v-form>
  </v-card>
</template>
