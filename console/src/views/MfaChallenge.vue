<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { UiCard, UiForm, UiInput, UiButton, UiAlert } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api } from '@/api/client'
import { useWebAuthn } from '@/composables/useWebAuthn'
import { useSignin, type SignInResponse } from '@/stores/signin'
import { mfaChallengeSchema } from '@/schemas'

const router = useRouter()
const signin = useSignin()
const keys = useWebAuthn()
const refusal = ref<string | null>(null)
const codeEl = ref<HTMLElement | null>(null)

// The second step offers the user's methods (feature 018): a security key
// first when the user has one and the browser supports it, otherwise the code
// form. An empty list (older server) means an authenticator app or a code.
const hasKey = computed(() => signin.methods.includes('webauthn'))
const canUseKey = computed(() => hasKey.value && keys.supported)
const hasTotp = computed(() => signin.methods.length === 0 || signin.methods.includes('totp'))
const mode = ref<'key' | 'code'>(canUseKey.value ? 'key' : 'code')
const codeHint = computed(() => (hasTotp.value ? 'Enter the 6-digit code from your authenticator app, or one of your recovery codes.' : 'Enter one of your recovery codes.'))

const form = useZodForm(mfaChallengeSchema, {
  initial: { code: '' },
  onSubmit: async (v) => {
    refusal.value = null
    try {
      const res = await api<SignInResponse>('POST', '/api/v1/signin/mfa', { challenge: signin.challenge, code: v.code })
      await signin.finish(res, (to) => router.push(to))
    } catch (err) {
      // TOTP or recovery code: the same refusal wording, the field cleared and refocused.
      refusal.value = signin.messageFor(err)
      form.values.code = ''
      codeEl.value?.querySelector('input')?.focus()
      throw err
    }
  },
})

async function useKey(): Promise<void> {
  refusal.value = null
  const res = await keys.signIn(signin.challenge)
  if (res) {
    await signin.finish(res, (to) => router.push(to))
    return
  }
  refusal.value = keys.error.value
}

function switchTo(m: 'key' | 'code'): void {
  refusal.value = null
  mode.value = m
  if (m === 'code') setTimeout(() => codeEl.value?.querySelector('input')?.focus())
}

onMounted(async () => {
  if (!signin.challenge) await router.replace({ name: 'signin' })
  if (mode.value === 'code') codeEl.value?.querySelector('input')?.focus()
})
</script>

<template>
  <UiCard data-test="mfa">
    <h1 class="mb-2 text-xl font-semibold">Second factor</h1>
    <template v-if="mode === 'key'">
      <p class="mb-4 text-sm text-base-content/70">Insert or touch your security key when your browser asks.</p>
      <div class="flex flex-col gap-3">
        <UiAlert v-if="refusal" kind="error" role="alert" data-test="error">{{ refusal }}</UiAlert>
        <UiButton block icon="mdi-key" :loading="keys.busy.value" data-test="use-key" @click="useKey">Use security key</UiButton>
        <UiButton variant="text" block data-test="use-code" @click="switchTo('code')">{{ hasTotp ? 'Use an authenticator code or a recovery code' : 'Use a recovery code' }}</UiButton>
      </div>
    </template>
    <template v-else>
      <p class="mb-4 text-sm text-base-content/70">{{ codeHint }}</p>
      <UiAlert v-if="hasKey && !keys.supported" kind="info" class="mb-4" data-test="key-unsupported">This browser does not support security keys. Use another method.</UiAlert>
      <UiForm :form="form">
        <div class="flex flex-col gap-3">
          <div ref="codeEl"><UiInput v-bind="form.field('code')" label="Code" autocomplete="one-time-code" inputmode="numeric" required data-test="code" /></div>
          <UiAlert v-if="refusal" kind="error" role="alert" data-test="error">{{ refusal }}</UiAlert>
          <UiButton type="submit" block :loading="form.submitting.value" data-test="submit">Continue</UiButton>
          <UiButton v-if="canUseKey" variant="text" block data-test="switch-key" @click="switchTo('key')">Use a security key instead</UiButton>
        </div>
      </UiForm>
    </template>
  </UiCard>
</template>
