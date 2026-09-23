<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { UiPage, UiCard, UiAlert, UiButton, UiForm, UiInput, UiSelect, UiDataTable, UiStatusChip, type Column, type SelectOption } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { api, ApiError } from '@/api/client'
import { auditEventTypes, reasonMessage } from '@/api/vocab'
import { auditFilterSchema } from '@/schemas'

/** One row of GET /api/v1/admin/audit (internal/audit.Item). */
interface AuditEvent {
  ts: string
  event_type: string
  actor_user_id: string | null
  actor_kind: string
  subject_kind?: string
  subject_id: string | null
  outcome: string
  reason?: string
  correlation_id?: string
  details: unknown
}
const items = ref<AuditEvent[]>([])
const next = ref<string | undefined>(undefined)
const error = ref<string | null>(null)
const eventOptions: SelectOption[] = auditEventTypes.map((t) => ({ title: t, value: t }))
const filter = useZodForm(auditFilterSchema, { initial: { user_id: '', from: '', to: '' }, onSubmit: (f) => load(f, false) })
type Filter = ReturnType<typeof auditFilterSchema.parse>
async function load(f: Filter, more: boolean): Promise<void> {
  error.value = null
  try {
    const page = await api<{ items: AuditEvent[]; next_cursor?: string }>('GET', '/api/v1/admin/audit', undefined, { query: { event_type: f.event_type, user_id: f.user_id || undefined, from: f.from, to: f.to, cursor: more ? next.value : undefined } })
    items.value = more ? [...items.value, ...page.items] : page.items
    next.value = page.next_cursor
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load the audit trail.'
  }
}
const apply = () => void filter.submit()
const loadMore = () => {
  const f = filter.validate()
  if (f) void load(f, true)
}
onMounted(apply)
const rows = computed(() => items.value.map((e, i) => ({ ...e, id: e.ts + ':' + i })))
const columns: Column<(typeof rows.value)[number]>[] = [
  { key: 'ts', label: 'Time', format: (e) => new Date(e.ts).toLocaleString() },
  { key: 'event_type', label: 'Event' },
  { key: 'actor', label: 'Actor', format: (e) => [e.actor_kind, e.actor_user_id ?? ''].filter(Boolean).join(' '), hideOnStack: true },
  { key: 'subject', label: 'Subject', format: (e) => [e.subject_kind ?? '', e.subject_id ?? ''].filter(Boolean).join(' ') },
  { key: 'outcome', label: 'Outcome', width: 'sm' },
  { key: 'reason', label: 'Reason', hideOnStack: true },
]
</script>

<template>
  <UiPage title="Audit trail">
    <template #filters>
      <UiForm :form="filter" class="w-full">
        <div class="grid grid-cols-2 gap-2 md:grid-cols-12 md:items-end">
          <div class="col-span-2 md:col-span-3"><UiSelect v-bind="filter.field('event_type')" label="Event" :options="eventOptions" size="sm" data-test="filter-event" /></div>
          <div class="col-span-2 md:col-span-3"><UiInput v-bind="filter.field('user_id')" label="Actor user id" size="sm" data-test="filter-user" @enter="apply" /></div>
          <div class="md:col-span-2"><UiInput v-bind="filter.field('from')" label="From" type="datetime-local" size="sm" data-test="filter-from" /></div>
          <div class="md:col-span-2"><UiInput v-bind="filter.field('to')" label="To" type="datetime-local" size="sm" data-test="filter-to" /></div>
          <div class="col-span-2 md:col-span-2"><UiButton block size="sm" data-test="apply" @click="apply">Apply</UiButton></div>
        </div>
      </UiForm>
    </template>
    <UiAlert v-if="error" kind="error" class="mb-3" data-test="error">{{ error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="rows" :columns="columns" caption="Audit events" empty-title="No events" :has-more="!!next" :row-attrs="() => ({ 'data-test': 'audit-row' })" data-test="audit" @load-more="loadMore">
        <template #cell-outcome="{ row }"><UiStatusChip :status="row.outcome" :colors="{ ok: 'success', refused: 'error', denied: 'error' }" /></template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
