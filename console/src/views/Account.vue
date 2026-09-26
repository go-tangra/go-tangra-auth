<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { UiPage, UiCard, UiForm, UiInput, UiSecretField, UiButton, UiAlert, UiIcon } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useMfa } from '@/composables/useMfa'
import type { MfaState } from '@/composables/useWebAuthn'
import { announceSessionChanged, useSession } from '@/stores/session'
import { changePasswordSchema, mfaEnrolSchema, totpSchema } from '@/schemas'
import ProfileForm from '@/components/ProfileForm.vue'
import RecoveryCodes from '@/components/RecoveryCodes.vue'
import SecurityKeys from '@/components/SecurityKeys.vue'

const session = useSession()
async function profileChanged(): Promise<void> {
  await session.load(true)
  announceSessionChanged()
}

// --- password ---
const pwDone = ref(false)
const pwError = ref<string | null>(null)
const password = useZodForm(changePasswordSchema(), {
  initial: { current_password: '', new_password: '', confirm: '' },
  onSubmit: async (v) => {
    pwDone.value = false
    pwError.value = null
    try {
      await api('POST', '/api/v1/me/password', { current_password: v.current_password, new_password: v.new_password })
      pwDone.value = true
    } catch (err) {
      pwError.value = err instanceof ApiError ? (err.reason === 'invalid_credentials' ? 'Your current password was not accepted.' : reasonMessage(err.reason)) : 'Could not change the password.'
      throw err
    } finally {
      password.reset({ current_password: '', new_password: '', confirm: '' })
    }
  },
})

// --- second factors (authenticator app + security keys, feature 018) ---
const { enrolment, qr, recoveryCodes, error: mfaError, busy: mfaBusy, start, confirm } = useMfa()
const mfaNotice = ref<string | null>(null)
const mfaState = ref<MfaState | null>(null)
async function loadFactors(): Promise<void> {
  try {
    const st = await api<MfaState>('GET', '/api/v1/me/mfa')
    mfaState.value = typeof st?.totp === 'boolean' ? st : null
  } catch {
    mfaState.value = null
  }
}
onMounted(loadFactors)
// Older servers have no /me/mfa: the session's flag then means the app.
const totpOn = computed(() => (mfaState.value ? mfaState.value.totp : !!session.user?.mfa_enabled))
const keysOn = computed(() => mfaState.value?.webauthn?.enabled === true)
async function factorsChanged(): Promise<void> {
  await Promise.all([loadFactors(), session.load(true)])
}
const enrol = useZodForm(mfaEnrolSchema, {
  initial: { code: '' },
  onSubmit: async (v) => {
    if (!(await confirm(v.code))) throw new Error('invalid_code')
    enrol.values.code = ''
    await factorsChanged()
  },
})
const disableForm = useZodForm(totpSchema, {
  initial: { code: '' },
  onSubmit: async (v) => {
    mfaNotice.value = null
    try {
      await api('POST', '/api/v1/me/mfa/disable', { code: v.code })
      await factorsChanged()
      mfaNotice.value = 'Authenticator app removed.'
    } catch (err) {
      mfaNotice.value = err instanceof ApiError ? (err.reason === 'mfa_required' ? 'Your organisation requires a second factor; add another one before removing this one.' : reasonMessage(err.reason)) : 'Could not disable.'
      throw err
    } finally {
      disableForm.reset({ code: '' })
    }
  },
})
const regenForm = useZodForm(totpSchema, {
  initial: { code: '' },
  onSubmit: async (v) => {
    mfaNotice.value = null
    try {
      const res = await api<{ recovery_codes: string[] }>('POST', '/api/v1/me/mfa/recovery-codes', { code: v.code })
      recoveryCodes.value = res.recovery_codes
    } catch (err) {
      mfaNotice.value = err instanceof ApiError && err.reason === 'invalid_code' ? 'That code was not accepted.' : 'Could not regenerate the codes.'
      throw err
    } finally {
      regenForm.reset({ code: '' })
    }
  },
})
</script>

<template>
  <UiPage title="Account">
    <UiCard title="Profile" class="mb-4" data-test="profile-card">
      <ProfileForm profile-path="/api/v1/me/profile" avatar-upload-path="/api/v1/me/avatar" avatar-remove-path="/api/v1/me/avatar" @changed="profileChanged" />
    </UiCard>
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <UiCard title="Change password" data-test="password-card">
        <UiForm :form="password">
          <div class="flex flex-col gap-3">
            <UiSecretField v-bind="password.field('current_password')" label="Current password" autocomplete="current-password" required data-test="current" />
            <UiSecretField v-bind="password.field('new_password')" label="New password" autocomplete="new-password" required data-test="new" />
            <UiSecretField v-bind="password.field('confirm')" label="Confirm new password" autocomplete="new-password" required data-test="confirm" />
            <UiAlert v-if="pwError" kind="error" data-test="pw-error">{{ pwError }}</UiAlert>
            <UiAlert v-if="pwDone" kind="success" data-test="pw-done">Password changed. Other devices were signed out.</UiAlert>
            <div><UiButton type="submit" :loading="password.submitting.value" data-test="pw-submit">Change password</UiButton></div>
          </div>
        </UiForm>
      </UiCard>
      <UiCard title="Second factors" data-test="mfa-card">
        <UiAlert v-if="mfaNotice" kind="info" class="mb-4" data-test="mfa-notice">{{ mfaNotice }}</UiAlert>
        <template v-if="recoveryCodes.length > 0">
          <UiAlert kind="success" class="mb-4">Save these recovery codes now — they are shown only once.</UiAlert>
          <RecoveryCodes :codes="recoveryCodes" class="mb-4" />
          <UiButton variant="text" data-test="codes-dismiss" @click="recoveryCodes = []">I have saved them</UiButton>
        </template>
        <template v-else-if="totpOn">
          <p class="mb-4 flex items-center gap-1"><UiIcon name="mdi-shield-check" class="text-success" />Authenticator app enabled.</p>
          <UiForm :form="regenForm" class="mb-4">
            <div class="flex flex-wrap items-end gap-2">
              <UiInput v-bind="regenForm.field('code')" label="Current code to regenerate recovery codes" inputmode="numeric" class="grow" data-test="regen-code" />
              <UiButton type="submit" variant="outline" :loading="regenForm.submitting.value" data-test="regen">New recovery codes</UiButton>
            </div>
          </UiForm>
          <UiForm :form="disableForm">
            <div class="flex flex-wrap items-end gap-2">
              <UiInput v-bind="disableForm.field('code')" label="Current code to disable" inputmode="numeric" class="grow" data-test="disable-code" />
              <UiButton type="submit" variant="outline" color="error" :loading="disableForm.submitting.value" data-test="disable">Remove authenticator app</UiButton>
            </div>
          </UiForm>
        </template>
        <template v-else-if="enrolment">
          <div class="mb-4 text-center">
            <img v-if="qr" :src="qr" alt="Authenticator enrolment QR code" width="192" height="192" class="mx-auto rounded-box" data-test="qr">
            <p class="mt-2 text-xs">Manual key: <code class="select-all" data-test="secret">{{ enrolment.secret }}</code></p>
          </div>
          <UiForm :form="enrol">
            <div class="flex flex-col gap-3">
              <UiInput v-bind="enrol.field('code')" label="6-digit code" inputmode="numeric" autocomplete="one-time-code" required data-test="code" />
              <UiAlert v-if="mfaError" kind="error" data-test="mfa-error">{{ mfaError }}</UiAlert>
              <div><UiButton type="submit" :loading="mfaBusy" data-test="confirm-enrol">Confirm</UiButton></div>
            </div>
          </UiForm>
        </template>
        <template v-else>
          <p class="mb-4">No authenticator app. Add one to protect your account.</p>
          <UiButton :loading="mfaBusy" data-test="enrol" @click="start">Set up authenticator</UiButton>
        </template>
        <template v-if="keysOn && mfaState && recoveryCodes.length === 0">
          <h3 class="mb-2 mt-6 font-semibold">Security keys</h3>
          <p v-if="mfaState.recovery_codes_left > 0" class="mb-2 text-xs text-base-content/70" data-test="codes-left">{{ mfaState.recovery_codes_left }} unused recovery codes.</p>
          <SecurityKeys :keys="mfaState.keys" :rp-id="mfaState.webauthn?.rp_id ?? ''" :totp="mfaState.totp" @changed="factorsChanged" @codes="(c) => (recoveryCodes = c)" />
        </template>
      </UiCard>
    </div>
  </UiPage>
</template>
