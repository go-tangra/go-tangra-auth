<script setup lang="ts">
import { ref } from 'vue'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useMfa } from '@/composables/useMfa'
import { announceSessionChanged, useSession } from '@/stores/session'
import ProfileForm from '@/components/ProfileForm.vue'

const session = useSession()

async function profileChanged(): Promise<void> {
  await session.load(true)
  announceSessionChanged()
}
const current = ref('')
const next = ref('')
const confirmPw = ref('')
const pwError = ref<string | null>(null)
const pwDone = ref(false)
const pwBusy = ref(false)

async function changePassword(): Promise<void> {
  pwError.value = null
  pwDone.value = false
  if (next.value !== confirmPw.value) {
    pwError.value = 'The new passwords do not match.'
    return
  }
  pwBusy.value = true
  try {
    await api('POST', '/api/v1/me/password', { current_password: current.value, new_password: next.value })
    pwDone.value = true
  } catch (err) {
    pwError.value = err instanceof ApiError ? (err.reason === 'invalid_credentials' ? 'Your current password was not accepted.' : reasonMessage(err.reason)) : 'Could not change the password.'
  } finally {
    pwBusy.value = false
    current.value = ''
    next.value = ''
    confirmPw.value = ''
  }
}

const { enrolment, qr, recoveryCodes, error: mfaError, busy: mfaBusy, start, confirm } = useMfa()
const code = ref('')
const disableCode = ref('')
const regenCode = ref('')
const mfaNotice = ref<string | null>(null)

async function confirmEnrolment(): Promise<void> {
  if (await confirm(code.value)) {
    code.value = ''
    await session.load(true)
  }
}

async function disable(): Promise<void> {
  mfaNotice.value = null
  try {
    await api('POST', '/api/v1/me/mfa/disable', { code: disableCode.value })
    await session.load(true)
    mfaNotice.value = 'Second factor disabled.'
  } catch (err) {
    mfaNotice.value = err instanceof ApiError ? (err.reason === 'mfa_required' ? 'Your organisation requires a second factor; it cannot be disabled.' : err.reason === 'invalid_code' ? 'That code was not accepted.' : reasonMessage(err.reason)) : 'Could not disable.'
  } finally {
    disableCode.value = ''
  }
}

async function regenerate(): Promise<void> {
  mfaNotice.value = null
  try {
    const res = await api<{ recovery_codes: string[] }>('POST', '/api/v1/me/mfa/recovery-codes', { code: regenCode.value })
    recoveryCodes.value = res.recovery_codes
  } catch (err) {
    mfaNotice.value = err instanceof ApiError && err.reason === 'invalid_code' ? 'That code was not accepted.' : 'Could not regenerate the codes.'
  } finally {
    regenCode.value = ''
  }
}
</script>

<template>
  <v-row>
    <v-col cols="12">
      <v-card class="mb-4" data-test="profile-card">
        <v-card-title>Profile</v-card-title>
        <v-card-text>
          <ProfileForm profile-path="/api/v1/me/profile" avatar-upload-path="/api/v1/me/avatar" avatar-remove-path="/api/v1/me/avatar" @changed="profileChanged" />
        </v-card-text>
      </v-card>
    </v-col>
    <v-col cols="12" md="6">
      <v-card data-test="password-card">
        <v-card-title>Change password</v-card-title>
        <v-card-text>
          <v-form @submit.prevent="changePassword">
            <v-text-field v-model="current" label="Current password" type="password" autocomplete="current-password" data-test="current" />
            <v-text-field v-model="next" label="New password" type="password" autocomplete="new-password" data-test="new" />
            <v-text-field v-model="confirmPw" label="Confirm new password" type="password" autocomplete="new-password" data-test="confirm" />
            <v-alert v-if="pwError" type="error" variant="tonal" density="compact" class="mb-4" data-test="pw-error">{{ pwError }}</v-alert>
            <v-alert v-if="pwDone" type="success" variant="tonal" density="compact" class="mb-4" data-test="pw-done">Password changed. Other devices were signed out.</v-alert>
            <v-btn type="submit" color="primary" :disabled="!current || next.length < 8 || pwBusy" :loading="pwBusy" data-test="pw-submit">Change password</v-btn>
          </v-form>
        </v-card-text>
      </v-card>
    </v-col>
    <v-col cols="12" md="6">
      <v-card data-test="mfa-card">
        <v-card-title>Second factor</v-card-title>
        <v-card-text>
          <v-alert v-if="mfaNotice" type="info" variant="tonal" density="compact" class="mb-4" data-test="mfa-notice">{{ mfaNotice }}</v-alert>
          <template v-if="recoveryCodes.length > 0">
            <v-alert type="success" variant="tonal" class="mb-4">Save these recovery codes now — they are shown only once.</v-alert>
            <ul class="mb-4" style="columns: 2; list-style: none; padding: 0" data-test="recovery-codes">
              <li v-for="c in recoveryCodes" :key="c"><code>{{ c }}</code></li>
            </ul>
            <v-btn variant="text" data-test="codes-dismiss" @click="recoveryCodes = []">I have saved them</v-btn>
          </template>
          <template v-else-if="session.user?.mfa_enabled">
            <p class="mb-4"><v-icon color="success" class="mr-1">mdi-shield-check</v-icon>Enabled with an authenticator app.</p>
            <v-text-field v-model.trim="regenCode" label="Current code to regenerate recovery codes" data-test="regen-code" />
            <v-btn variant="outlined" class="mb-6" :disabled="!/^\d{6}$/.test(regenCode)" data-test="regen" @click="regenerate">New recovery codes</v-btn>
            <v-text-field v-model.trim="disableCode" label="Current code to disable" data-test="disable-code" />
            <v-btn color="error" variant="outlined" :disabled="!/^\d{6}$/.test(disableCode)" data-test="disable" @click="disable">Disable second factor</v-btn>
          </template>
          <template v-else-if="enrolment">
            <div class="text-center mb-4">
              <img v-if="qr" :src="qr" alt="Authenticator enrolment QR code" width="192" height="192" data-test="qr">
              <p class="text-caption mt-2">Manual key: <code data-test="secret">{{ enrolment.secret }}</code></p>
            </div>
            <v-form @submit.prevent="confirmEnrolment">
              <v-text-field v-model.trim="code" label="6-digit code" inputmode="numeric" autocomplete="one-time-code" data-test="code" />
              <v-alert v-if="mfaError" type="error" variant="tonal" density="compact" class="mb-4" data-test="mfa-error">{{ mfaError }}</v-alert>
              <v-btn type="submit" color="primary" :disabled="!/^\d{6}$/.test(code) || mfaBusy" :loading="mfaBusy" data-test="confirm-enrol">Confirm</v-btn>
            </v-form>
          </template>
          <template v-else>
            <p class="mb-4">Not enrolled. Add an authenticator app to protect your account.</p>
            <v-btn color="primary" :loading="mfaBusy" data-test="enrol" @click="start">Set up authenticator</v-btn>
          </template>
        </v-card-text>
      </v-card>
    </v-col>
  </v-row>
</template>
