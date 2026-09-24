<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { UiPage, UiCard, UiAlert, UiButton, UiDataTable, UiSecretField, UiCopyButton, UiRecordDrawer, type Column } from '@go-tangra/ui'
import { zodToFields } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { clientSchema } from '@/schemas'

interface Client extends Record<string, unknown> {
  client_id: string
  display_name: string
  redirect_uris: string[]
  public: boolean
}
const clients = ref<Client[]>([])
const error = ref<string | null>(null)
const dialog = ref(false)
const created = ref<(Client & { client_secret?: string }) | null>(null)
const rows = computed(() => clients.value.map((c) => ({ ...c, id: c.client_id })))
const fields = zodToFields(clientSchema, { redirect_uris: { label: 'Redirect URIs (one per line, https)', type: 'textarea', cols: 12 }, public: { label: 'Public client (browser / mobile, PKCE only)', type: 'checkbox', cols: 12 } })

async function load(): Promise<void> {
  try {
    clients.value = await api<Client[]>('GET', '/api/v1/admin/clients')
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load applications.'
  }
}
const submit = (v: Record<string, unknown>) => api<Client & { client_secret?: string }>('POST', '/api/v1/admin/clients', v)
async function saved(c: unknown): Promise<void> {
  // The secret is shown once, in a masked field with copy; never stored client-side.
  created.value = c as Client & { client_secret?: string }
  await load()
}
onMounted(load)
const columns: Column<(typeof rows.value)[number]>[] = [
  { key: 'display_name', label: 'Name', sortable: true },
  { key: 'client_id', label: 'Client id' },
  { key: 'public', label: 'Type', format: (c) => (c.public ? 'public (PKCE)' : 'confidential'), width: 'sm' },
  { key: 'redirect_uris', label: 'Redirect URIs', format: (c) => c.redirect_uris.join(', '), hideOnStack: true },
]
</script>

<template>
  <UiPage title="Applications">
    <template #actions><UiButton icon="mdi-plus" data-test="client-open" @click="dialog = true">Register</UiButton></template>
    <UiAlert v-if="error" kind="error" class="mb-3" data-test="error">{{ error }}</UiAlert>
    <UiAlert v-if="created" kind="success" class="mb-4" data-test="created">
      <div>Client id: <code class="select-all" data-test="client-id">{{ created.client_id }}</code></div>
      <div v-if="created.client_secret" class="mt-2 flex flex-wrap items-end gap-2">
        <UiSecretField id="client-secret" :model-value="created.client_secret" label="Client secret (shown once)" readonly class="grow" data-test="client-secret" />
        <UiCopyButton :value="created.client_secret" label="Copy client secret" />
      </div>
      <UiButton size="sm" variant="text" class="mt-2" data-test="created-dismiss" @click="created = null">Dismiss</UiButton>
    </UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="rows" :columns="columns" caption="Applications" empty-title="No applications registered" :row-attrs="() => ({ 'data-test': 'client-row' })" data-test="clients">
        <template #cell-client_id="{ row }"><code class="text-xs">{{ row.client_id }}</code></template>
      </UiDataTable>
    </UiCard>
    <UiRecordDrawer v-model="dialog" close-on-save title="Register an application" :schema="clientSchema" :fields="fields" :initial="{ display_name: '', redirect_uris: '', public: true }" :submit="submit" save-label="Register" size="md" data-test="client-dialog" @saved="saved" />
  </UiPage>
</template>
