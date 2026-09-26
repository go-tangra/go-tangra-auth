<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiDataTable, UiBadge, UiTooltip, useConfirm, type Column } from '@go-tangra/ui'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { roleClonable, roleLocked, roleOrigin, useRoles, type Role } from '@/composables/useRoles'
import CloneRoleDialog from './CloneRoleDialog.vue'

const router = useRouter()
const confirm = useConfirm()
const { roles, load } = useRoles()
const error = ref<string | null>(null)
const busy = ref(false)
const cloning = ref<Role | null>(null)
type Row = Role & Record<string, unknown> & { id: string }
const rows = computed<Row[]>(() => roles.value.map((r) => ({ ...r, id: r.id ?? '' })))
/** Origin badge: built-in, the providing module's name, or custom. */
function originLabel(r: Role): string {
  const o = roleOrigin(r)
  if (o === 'builtin') return 'built-in'
  if (o === 'module') return r.module_display_name || r.module || 'module'
  return 'custom'
}
const originColor = (r: Role) => ({ builtin: 'primary', module: 'info', custom: 'neutral' } as const)[roleOrigin(r)]
const retiredHint = (r: Role) => `No longer provided by ${r.module_display_name || r.module || 'its module'}; kept for existing assignments`
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
function cloned(r: Role): void {
  cloning.value = null
  if (r.id) void router.push({ name: 'admin-role', params: { id: r.id } })
  else void load()
}
const open = (r: Row) => router.push({ name: 'admin-role', params: { id: r.id } })
onMounted(load)
const columns: Column<Row>[] = [
  { key: 'display_name', label: 'Role', sortable: true },
  { key: 'slug', label: 'Slug', hideOnStack: true },
  { key: 'permissions', label: 'Permissions', format: (r) => (roleOrigin(r) === 'builtin' ? 'defined by the platform' : (r.permissions ?? []).join(', ')) },
]
</script>

<template>
  <UiPage title="Roles">
    <template #actions><UiButton icon="mdi-plus" data-test="new-role" @click="router.push({ name: 'admin-role-new' })">New role</UiButton></template>
    <UiAlert v-if="error" kind="error" class="mb-3" data-test="error">{{ error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="rows" :columns="columns" caption="Roles" empty-title="No roles" :row-attrs="() => ({ 'data-test': 'role-row' })" data-test="roles">
        <template #cell-display_name="{ row }">
          {{ row.display_name }}
          <UiBadge size="xs" :color="originColor(row)" soft data-test="origin">{{ originLabel(row) }}</UiBadge>
          <UiTooltip v-if="row.retired" :text="retiredHint(row)"><UiBadge size="xs" color="warning" :title="retiredHint(row)" data-test="retired">retired</UiBadge></UiTooltip>
        </template>
        <template #cell-slug="{ row }"><code class="text-xs">{{ row.slug }}</code></template>
        <template #actions="{ row }">
          <UiButton v-if="roleLocked(row)" size="xs" variant="text" data-test="view" @click="open(row)">View</UiButton>
          <UiButton v-else size="xs" variant="text" data-test="edit" @click="open(row)">Edit</UiButton>
          <UiButton v-if="roleClonable(row)" size="xs" variant="text" data-test="clone" @click="cloning = row">Clone</UiButton>
          <UiButton v-if="!roleLocked(row)" size="xs" variant="text" color="error" :disabled="busy" data-test="remove" @click="remove(row)">Remove</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
    <CloneRoleDialog :source="cloning" @close="cloning = null" @cloned="cloned" />
  </UiPage>
</template>
