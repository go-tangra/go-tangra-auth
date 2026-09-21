<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api } from '@/api/client'
import type { components } from '@/api/schema'

type Session = components['schemas']['Session']

const sessions = ref<Session[]>([])
const error = ref<string | null>(null)
const busy = ref(false)

async function load(): Promise<void> {
  error.value = null
  try {
    sessions.value = await api<Session[]>('GET', '/api/v1/sessions')
  } catch {
    error.value = 'Could not load your sessions.'
  }
}

async function revoke(id: string | undefined): Promise<void> {
  if (!id) return
  busy.value = true
  try {
    await api('POST', `/api/v1/sessions/${encodeURIComponent(id)}/revoke`)
    await load()
  } catch {
    error.value = 'Could not end that session.'
  } finally {
    busy.value = false
  }
}

async function revokeOthers(): Promise<void> {
  for (const s of sessions.value) if (!s.current) await revoke(s.id)
}

onMounted(load)
</script>

<template>
  <v-card>
    <v-card-title>Your sessions</v-card-title>
    <v-card-text>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-4" data-test="error">{{ error }}</v-alert>
      <v-table data-test="sessions">
        <thead>
          <tr>
            <th>Device</th>
            <th>Started</th>
            <th>Last seen</th>
            <th>Expires</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr v-for="s in sessions" :key="s.id" :data-test="s.current ? 'session-current' : 'session'">
            <td>{{ s.user_agent || 'unknown' }} <v-chip v-if="s.current" size="x-small" color="primary" class="ml-2">this device</v-chip></td>
            <td>{{ s.created_at }}</td>
            <td>{{ s.last_seen_at }}</td>
            <td>{{ s.expires_at }}</td>
            <td class="text-right">
              <v-btn v-if="!s.current" size="small" variant="text" color="error" :disabled="busy" data-test="revoke" @click="revoke(s.id)">End</v-btn>
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
    <v-card-actions>
      <v-btn color="error" variant="outlined" :disabled="busy || sessions.filter((s) => !s.current).length === 0" data-test="revoke-others" @click="revokeOthers">
        Sign out everywhere else
      </v-btn>
    </v-card-actions>
  </v-card>
</template>
