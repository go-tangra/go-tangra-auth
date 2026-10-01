<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { UiPage, UiCard, UiAlert, UiButton, UiDataTable, UiStatusChip, UiRecordDrawer, type Column } from '@go-tangra/ui'
import { zodToFields } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { tenantSchema } from '@/schemas'
import { usePagedList, TENANT_LIST } from '@/composables/usePagedList'

export interface Tenant extends Record<string, unknown> {
  id: string
  slug: string
  display_name: string
  status: string
  kind: string
  created_at: string
}

const error = ref<string | null>(null)
// --- server paging and sorting (page / size / sort in the URL: ?tenants.page=…) ---
const list = usePagedList<Tenant>('tenants', '/api/v1/operator/tenants', TENANT_LIST, () => ({}),
  (err) => { error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load tenants.' })
const tenants = list.items
const notice = ref<string | null>(null)
const create = ref(false)
const fields = zodToFields(tenantSchema, { slug: { hint: 'lowercase letters, digits and dashes', cols: 12 }, display_name: { cols: 12 }, owner_email: { label: 'Owner email', cols: 12 } })

async function load(): Promise<void> {
  error.value = null
  await list.load()
}
const submit = (v: Record<string, unknown>) => api('POST', '/api/v1/operator/tenants', v).then(() => v)
async function saved(v: unknown): Promise<void> {
  notice.value = `Tenant ${String((v as { slug: string }).slug)} created; the owner invitation is on its way.`
  await load()
}
onMounted(load)
const columns: Column<Tenant>[] = [
  { key: 'display_name', label: 'Name', sortable: true },
  { key: 'slug', label: 'Slug', sortable: true },
  { key: 'status', label: 'Status', width: 'sm', sortable: true },
  { key: 'kind', label: 'Kind', width: 'sm', hideOnStack: true, sortable: true },
  { key: 'created_at', label: 'Created', format: (t) => new Date(t.created_at).toLocaleString(), hideOnStack: true, sortable: true },
]
</script>

<template>
  <UiPage title="Tenants">
    <template #actions><UiButton icon="mdi-domain-plus" data-test="create-open" @click="create = true">New tenant</UiButton></template>
    <UiAlert v-if="error" kind="error" class="mb-3" data-test="error">{{ error }}</UiAlert>
    <UiAlert v-if="notice" kind="success" class="mb-3" dismissible data-test="notice" @dismiss="notice = null">{{ notice }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="tenants" :columns="columns" :loading="list.loading.value" :total="list.total.value" :page="list.lq.page.value" :page-size="list.lq.pageSize.value" :sort="list.lq.sort.value" caption="Tenants" empty-title="No tenants yet" :row-attrs="() => ({ 'data-test': 'tenant-row' })" data-test="tenants" @update:page="list.lq.setPage" @update:page-size="list.lq.setPageSize" @update:sort="list.lq.setSort">
        <template #cell-display_name="{ row }"><RouterLink class="link link-primary" :to="{ name: 'operator-tenant', params: { id: row.id } }">{{ row.display_name }}</RouterLink></template>
        <template #cell-slug="{ row }"><code class="text-xs">{{ row.slug }}</code></template>
        <template #cell-status="{ row }"><UiStatusChip :status="row.status" :colors="{ active: 'success', suspended: 'error' }" data-test="status" /></template>
      </UiDataTable>
    </UiCard>
    <UiRecordDrawer v-model="create" close-on-save title="New tenant" :schema="tenantSchema" :fields="fields" :initial="{ slug: '', display_name: '', owner_email: '' }" :submit="submit" save-label="Create" size="md" data-test="create-dialog" @saved="saved" />
  </UiPage>
</template>
