<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { UiCard, UiForm, UiInput, UiButton, UiAlert, UiCheckbox, UiSection } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { leaveTo } from '@/base'
import { useMfa } from '@/composables/useMfa'
import { useWebAuthn } from '@/composables/useWebAuthn'
import { useSession } from '@/stores/session'
import { keyNameSchema, mfaEnrolSchema, recoveryCodesSavedSchema } from '@/schemas'
import RecoveryCodes from '@/components/RecoveryCodes.vue'

const router = useRouter()
const session = useSession()
const { enrolment, qr, recoveryCodes, error, busy, start, confirm } = useMfa()
const { supported: keySupported, busy: keyBusy, error: keyError, register } = useWebAuthn()
const keyAdded = ref(false)
onMounted(start)
const form = useZodForm(mfaEnrolSchema, {
  initial: { code: '' },
  onSubmit: async (v) => {
    if (!(await confirm(v.code))) throw new Error(error.value ?? 'invalid_code')
    form.values.code = ''
  },
})
// Security key (feature 018): the first factor of any kind issues recovery codes.
const keyForm = useZodForm(keyNameSchema, {
  initial: { name: '' },
  onSubmit: async (v) => {
    const res = await register(v.name)
    if (!res) throw new Error(keyError.value ?? 'registration_failed')
    keyAdded.value = true
    if (res.recovery_codes?.length) {
      recoveryCodes.value = res.recovery_codes
      return
    }
    await finish()
  },
})
async function finish(): Promise<void> {
  await session.load(true)
  await leaveTo((to) => router.replace(to), '/')
}
const saved = useZodForm(recoveryCodesSavedSchema, { initial: { saved: false }, onSubmit: finish })
</script>

<template>
  <UiCard data-test="mfa-enrol">
    <h1 class="mb-2 text-xl font-semibold">Set up your second factor</h1>
    <template v-if="recoveryCodes.length === 0">
      <p class="mb-4 text-sm text-base-content/70">Your organisation requires a second factor. Use an authenticator app or a security key such as a YubiKey.</p>
      <UiSection title="Authenticator app">
        <p class="mb-2 text-sm text-base-content/70">Scan the code with an authenticator app, then enter the 6-digit code it shows.</p>
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
      </UiSection>
      <UiSection title="Security key" data-test="key-section">
        <template v-if="keySupported">
          <p class="mb-2 text-sm text-base-content/70">Name the key, then insert or touch it when your browser asks.</p>
          <div class="flex flex-col gap-3">
            <UiInput v-bind="keyForm.field('name')" label="Key name" placeholder="YubiKey 5C – desk" autocomplete="off" required data-test="key-name" @enter="keyForm.submit()" />
            <UiAlert v-if="keyError" kind="error" role="alert" data-test="key-error">{{ keyError }}</UiAlert>
            <UiButton v-if="!keyAdded" block variant="outline" icon="mdi-key-plus" :loading="keyBusy" data-test="add-key" @click="keyForm.submit()">Add security key</UiButton>
          </div>
        </template>
        <p v-else class="text-sm text-base-content/70" data-test="key-unsupported">This browser does not support security keys. Use an authenticator app.</p>
      </UiSection>
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
