<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiDataTable, UiBadge, useConfirm, type Column } from '@freya/ui'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useRoles, type Role } from '@/composables/useRoles'

const router = useRouter()
const confirm = useConfirm()
const { roles, load } = useRoles()
const error = ref<string | null>(null)
const busy = ref(false)
type Row = Role & Record<string, unknown> & { id: string }
const rows = computed<Row[]>(() => roles.value.map((r) => ({ ...r, id: r.id ?? '' })))
async function remove(r: Row): Promise<void> {
  if (!r.id || !(await confirm.ask({ title: `Remove ${r.display_name}?`, text: 'People holding it lose its permissions.', danger: true, confirmLabel: 'Remove' }))) return
  busy.value = true
  error.value = null
  try {
    await api('POST', `/api/v1/admin/roles/${encodeURIComponent(r.id)}/remove`)
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not remove the role.'
  } finally {
    busy.value = false
  }
}
onMounted(load)
const columns: Column<Row>[] = [
  { key: 'display_name', label: 'Role', sortable: true },
  { key: 'slug', label: 'Slug', hideOnStack: true },
  { key: 'permissions', label: 'Permissions', format: (r) => (r.builtin ? 'defined by the platform' : (r.permissions ?? []).join(', ')) },
]
</script>

<template>
  <UiPage title="Roles">
    <template #actions><UiButton icon="mdi-plus" data-test="new-role" @click="router.push({ name: 'admin-role-new' })">New role</UiButton></template>
    <UiAlert v-if="error" kind="error" class="mb-3" data-test="error">{{ error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="rows" :columns="columns" caption="Roles" empty-title="No roles" :row-attrs="() => ({ 'data-test': 'role-row' })" data-test="roles">
        <template #cell-display_name="{ row }">{{ row.display_name }} <UiBadge v-if="row.builtin" size="xs" data-test="builtin">built-in</UiBadge></template>
        <template #cell-slug="{ row }"><code class="text-xs">{{ row.slug }}</code></template>
        <template #actions="{ row }">
          <UiButton v-if="!row.builtin" size="xs" variant="text" data-test="edit" @click="router.push({ name: 'admin-role', params: { id: row.id } })">Edit</UiButton>
          <UiButton v-if="!row.builtin" size="xs" variant="text" color="error" :disabled="busy" data-test="remove" @click="remove(row)">Remove</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
  </UiPage>
</template>
