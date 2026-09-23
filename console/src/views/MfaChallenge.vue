<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { UiCard, UiForm, UiInput, UiButton, UiAlert } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { api } from '@/api/client'
import { useSignin, type SignInResponse } from '@/stores/signin'
import { mfaChallengeSchema } from '@/schemas'

const router = useRouter()
const signin = useSignin()
const refusal = ref<string | null>(null)
const codeEl = ref<HTMLElement | null>(null)
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
onMounted(async () => {
  if (!signin.challenge) await router.replace({ name: 'signin' })
  codeEl.value?.querySelector('input')?.focus()
})
</script>

<template>
  <UiCard data-test="mfa">
    <h1 class="mb-2 text-xl font-semibold">Second factor</h1>
    <p class="mb-4 text-sm text-base-content/70">Enter the 6-digit code from your authenticator app, or one of your recovery codes.</p>
    <UiForm :form="form">
      <div class="flex flex-col gap-3">
        <div ref="codeEl"><UiInput v-bind="form.field('code')" label="Code" autocomplete="one-time-code" inputmode="numeric" required data-test="code" /></div>
        <UiAlert v-if="refusal" kind="error" role="alert" data-test="error">{{ refusal }}</UiAlert>
        <UiButton type="submit" block :loading="form.submitting.value" data-test="submit">Continue</UiButton>
      </div>
    </UiForm>
  </UiCard>
</template>
