<script setup lang="ts">
import { ref } from 'vue'
import { UiPage, UiCard, UiKeyValueTable, UiButton, UiAlert, UiTextarea } from '@freya/ui'
import { api } from '@/api/client'
import { useSession } from '@/stores/session'

const session = useSession()
const token = ref<{ access_token: string; expires_in: number } | null>(null)
const error = ref<string | null>(null)
async function mint(): Promise<void> {
  error.value = null
  try {
    token.value = await api<{ access_token: string; expires_in: number }>('POST', '/api/v1/session/token')
  } catch {
    error.value = 'Could not issue a token.'
  }
}
</script>

<template>
  <UiPage :title="'Welcome' + (session.user ? ', ' + (session.user.display_name || session.user.email) : '')">
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-2">
      <UiCard title="Your account">
        <UiKeyValueTable :items="[{ label: 'Organisation', value: session.tenant?.display_name ?? session.tenant?.slug ?? '' }, { label: 'Roles', value: session.roles.join(', ') || 'none' }, { label: 'Second factor', value: session.user?.mfa_enabled ? 'enabled' : 'not enrolled' }]" />
        <span class="sr-only" data-test="tenant">Organisation: {{ session.tenant?.display_name ?? session.tenant?.slug ?? '—' }}</span>
        <span class="sr-only" data-test="roles">Roles: {{ session.roles.join(', ') || 'none' }}</span>
        <span class="sr-only" data-test="mfa">Second factor: {{ session.user?.mfa_enabled ? 'enabled' : 'not enrolled' }}</span>
      </UiCard>
      <UiCard title="Access token">
        <p class="mb-4 text-sm text-base-content/70">Mint a short-lived token to call platform services on your behalf.</p>
        <UiButton data-test="mint" @click="mint">Get access token</UiButton>
        <UiAlert v-if="error" kind="error" class="mt-4">{{ error }}</UiAlert>
        <UiTextarea v-if="token" id="access-token" class="mt-4" :model-value="token.access_token" :label="`Expires in ${token.expires_in}s`" :rows="4" disabled data-test="token" />
      </UiCard>
    </div>
  </UiPage>
</template>
