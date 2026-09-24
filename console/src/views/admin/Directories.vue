<script setup lang="ts">
import { RouterLink } from 'vue-router'
import { computed, onMounted, ref } from 'vue'
import { UiPage, UiCard, UiAlert, UiButton, UiDataTable, UiDialog, UiBadge, type Column } from '@freya/ui'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import type { DirectoryConnection } from '@/schemas/directory'
import DirectoryDrawer from './DirectoryDrawer.vue'

const items = ref<DirectoryConnection[]>([])
const loading = ref(false)
const busy = ref(false)
const error = ref('')
const drawer = ref(false)
const editing = ref<DirectoryConnection | null>(null)
const deleting = ref<DirectoryConnection | null>(null)
type Row = DirectoryConnection & Record<string, unknown> & { id: string }
const rows = computed<Row[]>(() => items.value.map((c) => ({ ...c, id: c.id ?? '' })))
const columns: Column<Row>[] = [
  { key: 'name', label: 'Directory', sortable: true },
  { key: 'url', label: 'URL' },
  { key: 'tls_mode', label: 'TLS mode' },
  { key: 'last_test', label: 'Last test' },
]
const outcomes: Record<string, string> = { ok: 'OK', unreachable: 'Unreachable', target_refused: 'Target refused', timeout: 'Timeout', tls_failed: 'TLS failed', invalid_credentials: 'Invalid credentials', base_not_found: 'Base not found', directory_error: 'Directory error' }
function failed(err: unknown): void { error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not complete the directory request.' }
async function load(): Promise<void> {
  loading.value = true
  error.value = ''
  try { items.value = (await api<{ items: DirectoryConnection[] }>('GET', '/api/v1/admin/directories')).items }
  catch (err) { failed(err) }
  finally { loading.value = false }
}
function openNew(): void {
  editing.value = null
  error.value = ''
  drawer.value = true
}
async function edit(c: DirectoryConnection): Promise<void> {
  if (busy.value) return
  busy.value = true
  error.value = ''
  try {
    // List responses deliberately omit the CA PEM; load it before editing.
    editing.value = await api<DirectoryConnection>('GET', `/api/v1/admin/directories/${c.id}`)
    drawer.value = true
  } catch (err) { failed(err) }
  finally { busy.value = false }
}
function saved(c: DirectoryConnection): void {
  const i = items.value.findIndex((item) => item.id === c.id)
  if (i < 0) items.value.push(c)
  else items.value[i] = c
  drawer.value = false
  editing.value = null
}
async function remove(): Promise<void> {
  if (!deleting.value?.id || busy.value) return
  busy.value = true
  error.value = ''
  const id = deleting.value.id
  try {
    await api('POST', `/api/v1/admin/directories/${id}/remove`)
    items.value = items.value.filter((c) => c.id !== id)
    deleting.value = null
  } catch (err) { failed(err) }
  finally { busy.value = false }
}
onMounted(load)
</script>

<template>
  <UiPage title="Directories" data-test="directories">
    <template #actions><RouterLink :to="{ name: 'admin-directory-import' }" class="link link-primary">Import people</RouterLink><UiButton icon="mdi-plus" :disabled="busy || drawer" data-test="new-directory" @click="openNew">New directory</UiButton></template>
    <UiAlert v-if="error && !deleting" kind="error" class="mb-3">{{ error }} <UiButton variant="text" @click="load">Retry</UiButton></UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="rows" :columns="columns" :loading="loading" caption="Directory connections" empty-title="No directories yet" :row-attrs="() => ({ 'data-test': 'directory-row' })">
        <template #cell-name="{ row }"><span data-test="directory-name">{{ row.name }}</span></template>
        <template #cell-url="{ row }"><span data-test="directory-url">{{ row.url }}</span></template>
        <template #cell-tls_mode="{ row }"><span data-test="directory-tls">{{ row.tls_mode }}</span></template>
        <template #cell-last_test="{ row }">
          <UiBadge :color="!row.last_test ? 'neutral' : row.last_test.outcome === 'ok' ? 'success' : 'error'" :title="row.last_test?.at" data-test="last-test">{{ row.last_test ? outcomes[row.last_test.outcome ?? ''] ?? 'Directory error' : 'Never tested' }}</UiBadge>
          <div v-if="row.last_test?.at" class="mt-1 text-xs text-base-content/70"><time :datetime="row.last_test.at">{{ new Date(row.last_test.at).toLocaleString() }}</time></div>
        </template>
        <template #actions="{ row }">
          <UiButton size="xs" variant="text" :disabled="busy || drawer" data-test="edit" @click="edit(row)">Edit</UiButton>
          <UiButton size="xs" variant="text" color="error" :disabled="busy || drawer" data-test="delete-directory" @click="deleting = row; error = ''">Delete</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
    <DirectoryDrawer v-if="drawer" :connection="editing" @close="drawer = false; editing = null" @saved="saved" />
    <UiDialog :model-value="deleting !== null" :title="'Delete ' + (deleting?.name ?? '') + '?'" size="sm" :persistent="busy" data-test="delete-dialog" @update:model-value="deleting = null">
      <p data-test="delete-summary">Users already imported from {{ deleting?.name }} stay. The directory connection and its saved credentials will be removed.</p>
      <UiAlert v-if="error" kind="error" class="mt-3">{{ error }}</UiAlert>
      <template #actions>
        <UiButton variant="text" :disabled="busy" @click="deleting = null">Cancel</UiButton>
        <UiButton color="error" :loading="busy" :disabled="busy" data-test="confirm-delete" @click="remove">Delete directory</UiButton>
      </template>
    </UiDialog>
  </UiPage>
</template>
