<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError } from '@/api/client'
import { auditEventTypes, reasonMessage, type AuditEventType } from '@/api/vocab'
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
const eventType = ref<AuditEventType | null>(null)
const userId = ref('')
const from = ref('')
const to = ref('')
const error = ref<string | null>(null)

function query(cursor?: string): Record<string, string | undefined> {
  return {
    event_type: eventType.value ?? undefined,
    user_id: userId.value || undefined,
    from: from.value ? new Date(from.value).toISOString() : undefined,
    to: to.value ? new Date(to.value).toISOString() : undefined,
    cursor,
  }
}

async function load(more = false): Promise<void> {
  error.value = null
  try {
    const page = await api<{ items: AuditEvent[]; next_cursor?: string }>('GET', '/api/v1/admin/audit', undefined, { query: query(more ? next.value : undefined) })
    items.value = more ? [...items.value, ...page.items] : page.items
    next.value = page.next_cursor
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load the audit trail.'
  }
}

onMounted(() => load())
</script>

<template>
  <v-card>
    <v-card-title>Audit trail</v-card-title>
    <v-card-text>
      <v-row dense>
        <v-col cols="12" md="3"><v-select v-model="eventType" :items="[...auditEventTypes]" label="Event" clearable data-test="filter-event" /></v-col>
        <v-col cols="12" md="3"><v-text-field v-model.trim="userId" label="Actor user id" clearable data-test="filter-user" /></v-col>
        <v-col cols="6" md="2"><v-text-field v-model="from" label="From" type="datetime-local" data-test="filter-from" /></v-col>
        <v-col cols="6" md="2"><v-text-field v-model="to" label="To" type="datetime-local" data-test="filter-to" /></v-col>
        <v-col cols="12" md="2" class="d-flex align-center"><v-btn color="primary" block data-test="apply" @click="load()">Apply</v-btn></v-col>
      </v-row>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-2" data-test="error">{{ error }}</v-alert>
      <v-table density="compact" data-test="audit">
        <thead>
          <tr>
            <th>Time</th>
            <th>Event</th>
            <th>Actor</th>
            <th>Subject</th>
            <th>Outcome</th>
            <th>Reason</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="(e, i) in items" :key="i" data-test="audit-row">
            <td>{{ e.ts }}</td>
            <td>{{ e.event_type }}</td>
            <td>{{ e.actor_kind }} {{ e.actor_user_id ?? '' }}</td>
            <td>{{ e.subject_kind ?? '' }} {{ e.subject_id ?? '' }}</td>
            <td><v-chip size="x-small" :color="e.outcome === 'ok' ? 'success' : 'error'">{{ e.outcome }}</v-chip></td>
            <td>{{ e.reason ?? '' }}</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
    <v-card-actions>
      <v-btn v-if="next" variant="text" data-test="more" @click="load(true)">Load more</v-btn>
    </v-card-actions>
  </v-card>
</template>
