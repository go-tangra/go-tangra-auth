<script setup lang="ts">
import { ref } from 'vue'
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
  <v-row>
    <v-col cols="12" md="6">
      <v-card>
        <v-card-title>Welcome{{ session.user ? ', ' + (session.user.display_name || session.user.email) : '' }}</v-card-title>
        <v-card-text>
          <div data-test="tenant">Organisation: {{ session.tenant?.display_name ?? session.tenant?.slug ?? '—' }}</div>
          <div data-test="roles">Roles: {{ session.roles.join(', ') || 'none' }}</div>
          <div data-test="mfa">Second factor: {{ session.user?.mfa_enabled ? 'enabled' : 'not enrolled' }}</div>
        </v-card-text>
      </v-card>
    </v-col>
    <v-col cols="12" md="6">
      <v-card>
        <v-card-title>Access token</v-card-title>
        <v-card-text>
          <p class="text-body-2 mb-4">Mint a short-lived token to call platform services on your behalf.</p>
          <v-btn color="primary" data-test="mint" @click="mint">Get access token</v-btn>
          <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-4">{{ error }}</v-alert>
          <v-textarea v-if="token" class="mt-4" readonly auto-grow :model-value="token.access_token" :label="`Expires in ${token.expires_in}s`" data-test="token" />
        </v-card-text>
      </v-card>
    </v-col>
  </v-row>
</template>
