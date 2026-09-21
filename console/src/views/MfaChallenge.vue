<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { api } from '@/api/client'
import { useSignin, type SignInResponse } from '@/stores/signin'

const router = useRouter()
const signin = useSignin()
const code = ref('')
const error = ref<string | null>(null)
const busy = ref(false)
const canSubmit = computed(() => /^[A-Za-z0-9-]{6,16}$/.test(code.value) && !busy.value)

onMounted(async () => {
  if (!signin.challenge) await router.replace({ name: 'signin' })
})

async function submit(): Promise<void> {
  if (!canSubmit.value) return
  error.value = null
  busy.value = true
  try {
    const res = await api<SignInResponse>('POST', '/api/v1/signin/mfa', { challenge: signin.challenge, code: code.value })
    await signin.finish(res, (to) => router.push(to))
  } catch (err) {
    error.value = signin.messageFor(err)
    code.value = ''
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <v-card class="pa-6" data-test="mfa">
    <v-card-title class="text-h5 mb-2">Second factor</v-card-title>
    <p class="text-body-2 mb-4">Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
    <v-form @submit.prevent="submit">
      <v-text-field v-model.trim="code" label="Code" autocomplete="one-time-code" inputmode="numeric" data-test="code" autofocus />
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-4" role="alert" data-test="error">{{ error }}</v-alert>
      <v-btn type="submit" color="primary" block :disabled="!canSubmit" :loading="busy" data-test="submit">Continue</v-btn>
    </v-form>
  </v-card>
</template>
