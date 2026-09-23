<script setup lang="ts">
import { onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { UiCard, UiForm, UiInput, UiButton, UiAlert, UiCheckbox } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { leaveTo } from '@/base'
import { useMfa } from '@/composables/useMfa'
import { useSession } from '@/stores/session'
import { mfaEnrolSchema, recoveryCodesSavedSchema } from '@/schemas'
import RecoveryCodes from '@/components/RecoveryCodes.vue'

const router = useRouter()
const session = useSession()
const { enrolment, qr, recoveryCodes, error, busy, start, confirm } = useMfa()
onMounted(start)
const form = useZodForm(mfaEnrolSchema, {
  initial: { code: '' },
  onSubmit: async (v) => {
    if (!(await confirm(v.code))) throw new Error(error.value ?? 'invalid_code')
    form.values.code = ''
  },
})
const saved = useZodForm(recoveryCodesSavedSchema, {
  initial: { saved: false },
  onSubmit: async () => {
    await session.load(true)
    await leaveTo((to) => router.replace(to), '/')
  },
})
</script>

<template>
  <UiCard data-test="mfa-enrol">
    <h1 class="mb-2 text-xl font-semibold">Set up your second factor</h1>
    <p class="mb-4 text-sm text-base-content/70">Your organisation requires a second factor. Scan the code with an authenticator app, then enter the 6-digit code it shows.</p>
    <template v-if="recoveryCodes.length === 0">
      <div v-if="enrolment" class="mb-4 text-center">
        <img v-if="qr" :src="qr" alt="Authenticator enrolment QR code" width="192" height="192" class="mx-auto rounded-box" data-test="qr">
        <p class="mt-2 text-xs">Manual key: <code class="select-all" data-test="secret">{{ enrolment.secret }}</code></p>
      </div>
      <UiForm :form="form">
        <div class="flex flex-col gap-3">
          <UiInput v-bind="form.field('code')" label="6-digit code" inputmode="numeric" autocomplete="one-time-code" required data-test="code" />
          <UiAlert v-if="error" kind="error" role="alert" data-test="error">{{ error }}</UiAlert>
          <UiButton type="submit" block :loading="busy" data-test="confirm">Confirm</UiButton>
        </div>
      </UiForm>
    </template>
    <template v-else>
      <UiAlert kind="success" class="mb-4">Second factor enabled. Save these recovery codes now — they are shown only once.</UiAlert>
      <RecoveryCodes :codes="recoveryCodes" class="mb-4" />
      <UiForm :form="saved">
        <UiCheckbox v-bind="saved.field('saved')" label="I have saved my recovery codes" data-test="saved" />
        <UiButton type="submit" block class="mt-3" data-test="done">Continue</UiButton>
      </UiForm>
    </template>
  </UiCard>
</template>
