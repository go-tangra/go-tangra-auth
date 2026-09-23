<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { UiPage, UiCard, UiAlert, UiButton, UiDataTable, UiBadge, useConfirm, type Column } from '@freya/ui'
import { api } from '@/api/client'
import type { components } from '@/api/schema'

type Session = components['schemas']['Session'] & Record<string, unknown> & { id: string }
const sessions = ref<Session[]>([])
const error = ref<string | null>(null)
const busy = ref(false)
const confirm = useConfirm()
async function load(): Promise<void> {
  error.value = null
  try {
    sessions.value = (await api<Session[]>('GET', '/api/v1/sessions')).map((s) => ({ ...s, id: s.id ?? '' }))
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
  if (!(await confirm.ask({ title: 'Sign out everywhere else?', text: 'Every other device is signed out immediately.', danger: true, confirmLabel: 'Sign out others' }))) return
  for (const s of sessions.value) if (!s.current) await revoke(s.id)
}
onMounted(load)
const columns: Column<Session>[] = [
  { key: 'user_agent', label: 'Device', format: (s) => s.user_agent || 'unknown' },
  { key: 'created_at', label: 'Started', hideOnStack: true },
  { key: 'last_seen_at', label: 'Last seen' },
  { key: 'expires_at', label: 'Expires', hideOnStack: true },
]
</script>

<template>
  <UiPage title="Your sessions">
    <template #actions><UiButton variant="soft" color="error" :disabled="busy || sessions.filter((s) => !s.current).length === 0" data-test="revoke-others" @click="revokeOthers">Sign out everywhere else</UiButton></template>
    <UiAlert v-if="error" kind="error" class="mb-3" data-test="error">{{ error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="sessions" :columns="columns" caption="Sessions" empty-title="No sessions" :row-attrs="(s) => ({ 'data-test': s.current ? 'session-current' : 'session' })" data-test="sessions">
        <template #cell-user_agent="{ row }">{{ row.user_agent || 'unknown' }} <UiBadge v-if="row.current" color="primary" size="xs">this device</UiBadge></template>
        <template #actions="{ row }"><UiButton v-if="!row.current" size="xs" variant="text" color="error" :disabled="busy" data-test="revoke" @click="revoke(row.id)">End</UiButton></template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
