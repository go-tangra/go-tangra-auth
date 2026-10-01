<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { UiPage, UiCard, UiAlert, UiButton, UiDataTable, UiBadge, useConfirm, type Column } from '@go-tangra/ui'
import { api } from '@/api/client'
import type { components } from '@/api/schema'
import { usePagedList, SESSION_LIST } from '@/composables/usePagedList'

type Session = components['schemas']['Session'] & Record<string, unknown> & { id: string }
const error = ref<string | null>(null)
// --- server paging and sorting (page / size / sort in the URL: ?sessions.page=…) ---
const list = usePagedList<Session>('sessions', '/api/v1/sessions', SESSION_LIST, () => ({}), () => { error.value = 'Could not load your sessions.' })
const sessions = computed(() => list.items.value.map((s) => ({ ...s, id: s.id ?? '' })))
const busy = ref(false)
const confirm = useConfirm()
async function load(): Promise<void> {
  error.value = null
  await list.load()
}
async function end(id: string): Promise<void> {
  await api('POST', `/api/v1/sessions/${encodeURIComponent(id)}/revoke`)
}
async function revoke(id: string | undefined): Promise<void> {
  if (!id) return
  busy.value = true
  try {
    await end(id)
    await load()
  } catch {
    error.value = 'Could not end that session.'
  } finally {
    busy.value = false
  }
}
async function revokeOthers(): Promise<void> {
  if (!(await confirm.ask({ title: 'Sign out everywhere else?', text: 'Every other device is signed out immediately.', danger: true, confirmLabel: 'Sign out others' }))) return
  busy.value = true
  try {
    // Every live session, not only this page: the unpaged list.
    const all = await api<Session[]>('GET', '/api/v1/sessions')
    for (const s of all) if (!s.current && s.id) await end(s.id)
    await load()
  } catch {
    error.value = 'Could not end every other session.'
  } finally {
    busy.value = false
  }
}
onMounted(load)
const columns: Column<Session>[] = [
  { key: 'user_agent', label: 'Device', format: (s) => s.user_agent || 'unknown' },
  { key: 'created_at', label: 'Started', hideOnStack: true, sortable: true },
  { key: 'last_seen_at', label: 'Last seen', sortable: true },
  { key: 'expires_at', label: 'Expires', hideOnStack: true, sortable: true },
]
</script>

<template>
  <UiPage title="Your sessions">
    <template #actions><UiButton variant="soft" color="error" :disabled="busy || list.total.value <= 1" data-test="revoke-others" @click="revokeOthers">Sign out everywhere else</UiButton></template>
    <UiAlert v-if="error" kind="error" class="mb-3" data-test="error">{{ error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="sessions" :columns="columns" :loading="list.loading.value" :total="list.total.value" :page="list.lq.page.value" :page-size="list.lq.pageSize.value" :sort="list.lq.sort.value" caption="Sessions" empty-title="No sessions" :row-attrs="(s) => ({ 'data-test': s.current ? 'session-current' : 'session' })" data-test="sessions" @update:page="list.lq.setPage" @update:page-size="list.lq.setPageSize" @update:sort="list.lq.setSort">
        <template #cell-user_agent="{ row }">{{ row.user_agent || 'unknown' }} <UiBadge v-if="row.current" color="primary" size="xs">this device</UiBadge></template>
        <template #actions="{ row }"><UiButton v-if="!row.current" size="xs" variant="text" color="error" :disabled="busy" data-test="revoke" @click="revoke(row.id)">End</UiButton></template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
