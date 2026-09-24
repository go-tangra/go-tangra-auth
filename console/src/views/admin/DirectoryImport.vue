<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiInput, UiSelect, UiDataTable, UiStatusChip, type Column } from '@freya/ui'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { directorySearchSchema, directoryImportSchema, type DirectoryConnection, type DirectorySearchInput, type DirectorySearchResult, type DirectoryImportResult } from '@/schemas/directory'

const connections = ref<DirectoryConnection[]>([])
const connection = ref('')
const filter = ref('')
const base = ref('')
const scope = ref('')
const busy = ref(false)
const error = ref('')
const result = ref<DirectorySearchResult | null>(null)
const summary = ref('')
const issues = ref<string[]>([])
const selected = ref<string[]>([])
let lastSearch: DirectorySearchInput | null = null
type Row = NonNullable<DirectorySearchResult['items']>[number] & { id: string } & Record<string, unknown>
const rows = computed<Row[]>(() => (result.value?.items ?? []).map((item, i) => ({ ...item, id: String(i) })))
const options = computed(() => connections.value.filter((c) => c.id).map((c) => ({ title: c.name ?? '', value: c.id! })))
const columns: Column<Row>[] = [
  { key: 'selection', label: 'Select', width: 'sm' },
  { key: 'display_name', label: 'Name' },
  { key: 'email', label: 'Email' },
  { key: 'status', label: 'Status' },
]
const labels = { new: 'New', existing_user: 'Existing user', imported: 'Imported', invalid: 'Invalid' }
function selectable(row: Row): boolean { return !!row.uid && (row.status === 'new' || row.status === 'imported') }
const eligible = computed(() => [...new Set(rows.value.filter(selectable).map((row) => row.uid!))])
function selectAll(): void { selected.value = eligible.value.slice(0, 500) }
function failed(err: unknown): void {
  error.value = err instanceof ApiError
    ? err.reason === 'invalid_filter' && typeof err.detail?.message === 'string' ? err.detail.message : reasonMessage(err.reason)
    : 'Could not complete the directory request.'
}
watch(connection, () => {
  result.value = null
  selected.value = []
  summary.value = ''
  issues.value = []
  error.value = ''
  lastSearch = null
  filter.value = base.value = scope.value = ''
})
async function load(): Promise<void> {
  busy.value = true
  error.value = ''
  try { connections.value = (await api<{ items: DirectoryConnection[] }>('GET', '/api/v1/admin/directories')).items }
  catch (err) { failed(err) }
  finally { busy.value = false }
}
async function preview(input: DirectorySearchInput): Promise<void> {
  selected.value = []
  result.value = null
  result.value = await api<DirectorySearchResult>('POST', `/api/v1/admin/directories/${encodeURIComponent(connection.value)}/search`, input)
}
async function search(): Promise<void> {
  if (busy.value || !connection.value) return
  error.value = ''
  summary.value = ''
  issues.value = []
  result.value = null
  selected.value = []
  const parsed = directorySearchSchema.safeParse({ filter: filter.value, base: base.value, scope: scope.value })
  if (!parsed.success) { error.value = parsed.error.issues.map((i) => i.message).join(' '); return }
  busy.value = true
  lastSearch = parsed.data
  try { await preview(parsed.data) }
  catch (err) { failed(err) }
  finally { busy.value = false }
}
async function importSelected(): Promise<void> {
  if (busy.value || !connection.value || !lastSearch) return
  const parsed = directoryImportSchema.safeParse({ uids: selected.value.filter((uid) => eligible.value.includes(uid)) })
  if (!parsed.success) { error.value = parsed.error.issues.map((i) => i.message).join(' '); return }
  busy.value = true
  error.value = ''
  summary.value = ''
  issues.value = []
  const names = new Map(rows.value.map((row) => [row.uid, row.display_name]))
  try {
    const imported = await api<DirectoryImportResult>('POST', `/api/v1/admin/directories/${encodeURIComponent(connection.value)}/import`, parsed.data)
    summary.value = `Import finished: ${imported.created?.length ?? 0} created, ${imported.updated?.length ?? 0} updated, ${imported.skipped?.length ?? 0} skipped, ${imported.failed?.length ?? 0} failed.`
    issues.value = [...(imported.skipped ?? []), ...(imported.failed ?? [])].map((issue) => `${names.get(issue.uid) || issue.uid}: ${reasonMessage(issue.reason ?? 'internal')}`)
    await preview(lastSearch)
  } catch (err) { failed(err) }
  finally { busy.value = false }
}
onMounted(load)
</script>

<template>
  <UiPage title="Import from directory" data-test="directory-import">
    <p class="mb-3">Imported people cannot sign in until invited. Importing sends no email.</p>
    <UiSelect id="import-connection" v-model="connection" label="Directory connection" :options="options" :disabled="busy" data-test="connection" />
    <p v-if="!busy && !connections.length" class="my-3">No directory connections. <RouterLink :to="{ name: 'admin-directories' }" class="link link-primary">Manage directories</RouterLink></p>
    <form v-if="connection" class="my-4 grid gap-3" @submit.prevent="search">
      <UiInput id="import-filter" v-model="filter" label="LDAP filter" placeholder="(mail=*)" :disabled="busy" data-test="filter" />
      <UiInput id="import-base" v-model="base" label="Search base (optional)" :disabled="busy" data-test="base" />
      <UiSelect id="import-scope" v-model="scope" label="Scope (default: subtree)" :options="[{ title: 'One level', value: 'one' }, { title: 'Subtree', value: 'sub' }]" :disabled="busy" data-test="scope" />
      <UiButton type="submit" :disabled="busy" :loading="busy" data-test="search-directory">Search directory</UiButton>
    </form>
    <UiAlert v-if="error" kind="error" class="my-3" data-test="search-error">{{ error }}</UiAlert>
    <UiButton v-if="error && !connections.length" variant="text" :disabled="busy" @click="load">Retry</UiButton>
    <section v-if="summary" aria-live="polite" class="my-3">
      <p data-test="import-summary">{{ summary }}</p>
      <ul><li v-for="(issue, i) in issues" :key="i" data-test="import-issue">{{ issue }}</li></ul>
      <RouterLink :to="{ name: 'admin-users' }" class="link link-primary">View users</RouterLink>
    </section>
    <template v-if="result">
      <p class="my-3 break-all" data-test="effective-filter">Effective filter: {{ result.effective_filter }}</p>
      <UiAlert v-if="result.truncated" kind="warning" class="my-3" data-test="truncation">More entries matched. The size or time limit was reached; narrow the filter or search base.</UiAlert>
      <p v-if="result.out_of_scope" class="my-3">{{ result.out_of_scope }} entries outside the search base were excluded.</p>
      <div class="my-3 flex items-center gap-3">
        <UiButton variant="text" :disabled="busy || !eligible.length" data-test="select-all" @click="selectAll">Select all (up to 500)</UiButton>
        <UiButton variant="text" :disabled="busy || !selected.length" @click="selected = []">Clear selection</UiButton>
        <span>{{ selected.length }} selected (maximum 500)</span>
        <UiButton :disabled="busy || !selected.length" data-test="import" @click="importSelected">Import selected</UiButton>
      </div>
      <UiCard :padded="false">
        <UiDataTable :items="rows" :columns="columns" caption="Directory preview" empty-title="No matching people" :row-attrs="() => ({ 'data-test': 'preview-row' })">
          <template #cell-selection="{ row }">
            <input v-model="selected" type="checkbox" class="checkbox checkbox-sm" :value="row.uid" :aria-label="`Select ${row.display_name || row.email || row.uid}`" :disabled="busy || !selectable(row) || (selected.length >= 500 && !selected.includes(row.uid!))">
          </template>
          <template #cell-display_name="{ row }"><span data-test="preview-name">{{ row.display_name }}</span></template>
          <template #cell-email="{ row }"><span data-test="preview-email">{{ row.email || '—' }}</span></template>
          <template #cell-status="{ row }">
            <UiStatusChip :status="row.status ?? 'invalid'" :label="labels[row.status ?? 'invalid']" :colors="{ new: 'success', imported: 'neutral', existing_user: 'info', invalid: 'error' }" data-test="preview-status" />
            <p v-if="row.reason" data-test="preview-reason">{{ reasonMessage(row.reason) }}</p>
          </template>
        </UiDataTable>
      </UiCard>
    </template>
  </UiPage>
</template>
