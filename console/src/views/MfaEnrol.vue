<script setup lang="ts">
import { leaveTo } from '@/base'
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useMfa } from '@/composables/useMfa'
import { useSession } from '@/stores/session'

const router = useRouter()
const session = useSession()
const { enrolment, qr, recoveryCodes, error, busy, start, confirm } = useMfa()
const code = ref('')
const saved = ref(false)

onMounted(start)

async function submit(): Promise<void> {
  if (await confirm(code.value)) code.value = ''
}

async function done(): Promise<void> {
  await session.load(true)
  await leaveTo((to) => router.replace(to), '/')
}
</script>

<template>
  <v-card class="pa-6" data-test="mfa-enrol">
    <v-card-title class="text-h5 mb-2">Set up your second factor</v-card-title>
    <p class="text-body-2 mb-4">Your organisation requires a second factor. Scan the code with an authenticator app, then enter the 6-digit code it shows.</p>
    <template v-if="recoveryCodes.length === 0">
      <div v-if="enrolment" class="text-center mb-4">
        <img v-if="qr" :src="qr" alt="Authenticator enrolment QR code" width="192" height="192" data-test="qr">
        <p class="text-caption mt-2">Manual key: <code data-test="secret">{{ enrolment.secret }}</code></p>
      </div>
      <v-form @submit.prevent="submit">
        <v-text-field v-model.trim="code" label="6-digit code" inputmode="numeric" autocomplete="one-time-code" data-test="code" />
        <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-4" role="alert" data-test="error">{{ error }}</v-alert>
        <v-btn type="submit" color="primary" block :disabled="!/^\d{6}$/.test(code) || busy" :loading="busy" data-test="confirm">Confirm</v-btn>
      </v-form>
    </template>
    <template v-else>
      <v-alert type="success" variant="tonal" class="mb-4">Second factor enabled. Save these recovery codes now — they are shown only once.</v-alert>
      <ul class="mb-4 font-weight-medium" style="columns: 2; list-style: none; padding: 0" data-test="recovery-codes">
        <li v-for="c in recoveryCodes" :key="c"><code>{{ c }}</code></li>
      </ul>
      <v-checkbox v-model="saved" label="I have saved my recovery codes" data-test="saved" />
      <v-btn color="primary" block :disabled="!saved" data-test="done" @click="done">Continue</v-btn>
    </template>
  </v-card>
</template>
