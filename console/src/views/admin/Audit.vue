<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { UiPage, UiCard, UiAlert, UiButton, UiForm, UiInput, UiSelect, UiDataTable, UiStatusChip, type Column, type SelectOption } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { ApiError } from '@/api/client'
import { usePagedList, AUDIT_LIST } from '@/composables/usePagedList'
import { auditEventLabel, auditEventTypes, reasonMessage } from '@/api/vocab'
import { auditFilterSchema } from '@/schemas'

/** One row of GET /api/v1/admin/audit (internal/audit.Item). */
interface AuditEvent {
  id?: string
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
const error = ref<string | null>(null)
const eventOptions: SelectOption[] = auditEventTypes.map((t) => ({ title: auditEventLabel(t), value: t }))
type Filter = ReturnType<typeof auditFilterSchema.parse>
// --- server paging (page / size / order in the URL: ?audit.page=…); newest
// first; without From / To the server lists the last 7 days ---
const current = ref<Partial<Filter>>({})
const list = usePagedList<AuditEvent>('audit', '/api/v1/admin/audit', AUDIT_LIST,
  () => ({ event_type: current.value.event_type, user_id: current.value.user_id || undefined, from: current.value.from, to: current.value.to }),
  (err) => { error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load the audit trail.' })
const filter = useZodForm(auditFilterSchema, {
  initial: { user_id: '', from: '', to: '' },
  onSubmit: async (f) => {
    error.value = null
    current.value = f
    await list.refilter()
  },
})
const apply = () => void filter.submit()
onMounted(apply)
const windowHint = computed(() => (current.value.from || current.value.to ? '' : 'Showing the last 7 days. Set From / To for older events.'))
const rows = computed(() => list.items.value.map((e, i) => ({ ...e, id: e.id ?? e.ts + ':' + i })))
const columns: Column<(typeof rows.value)[number]>[] = [
  { key: 'ts', label: 'Time', format: (e) => new Date(e.ts).toLocaleString(), sortable: true },
  { key: 'event_type', label: 'Event', format: (e) => auditEventLabel(e.event_type) },
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
    <p v-if="windowHint" class="mb-2 text-sm text-base-content/70" data-test="audit-window">{{ windowHint }}</p>
    <UiCard :padded="false">
      <UiDataTable :items="rows" :columns="columns" :loading="list.loading.value" :total="list.total.value" :page="list.lq.page.value" :page-size="list.lq.pageSize.value" :sort="list.lq.sort.value" caption="Audit events" empty-title="No events" :row-attrs="() => ({ 'data-test': 'audit-row' })" data-test="audit" @update:page="list.lq.setPage" @update:page-size="list.lq.setPageSize" @update:sort="list.lq.setSort">
        <template #cell-outcome="{ row }"><UiStatusChip :status="row.outcome" :colors="{ ok: 'success', refused: 'error', denied: 'error' }" /></template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
