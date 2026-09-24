<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiInput, UiDataTable, UiDialog, UiRecordDrawer, type Column } from '@go-tangra/ui'
import { zodToFields } from '@go-tangra/ui/forms'
import { ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useGroups, type Group } from '@/stores/groups'
import { groupSchema } from '@/schemas'

const groups = useGroups()
const q = ref('')
const error = ref<string | null>(null)
const busy = ref(false)
const dialog = ref(false)
const editing = ref<Group | null>(null)
const confirmDelete = ref<Group | null>(null)
type Row = Group & Record<string, unknown> & { id: string }
const rows = computed<Row[]>(() => groups.items.map((g) => ({ ...g, id: g.id ?? '' })))
const fields = zodToFields(groupSchema, { description: { cols: 12 } })

function openNew(): void {
  editing.value = null
  error.value = null
  dialog.value = true
}
function openEdit(g: Group): void {
  editing.value = g
  error.value = null
  dialog.value = true
}
const submit = (v: Record<string, unknown>) => (editing.value?.id ? groups.update(editing.value.id, String(v.name), String(v.description ?? '')) : groups.create(String(v.name), String(v.description ?? '')))
async function remove(): Promise<void> {
  const g = confirmDelete.value
  if (!g?.id) return
  busy.value = true
  error.value = null
  try {
    await groups.remove(g.id, g.member_count ?? 0)
    confirmDelete.value = null
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not delete the group.'
    if (err instanceof ApiError && err.reason === 'member_count_mismatch') await groups.load(q.value)
  } finally {
    busy.value = false
  }
}
let timer: number | undefined
watch(q, () => {
  window.clearTimeout(timer)
  timer = window.setTimeout(() => void groups.load(q.value), 250)
})
onMounted(() => groups.load())
const columns: Column<Row>[] = [
  { key: 'name', label: 'Group', sortable: true },
  { key: 'member_count', label: 'Members', align: 'end', format: (g) => String(g.member_count ?? 0) },
  { key: 'roles', label: 'Roles', format: (g) => (g.roles ?? []).join(', '), hideOnStack: true },
]
</script>

<template>
  <UiPage title="Groups" data-test="groups">
    <template #actions><UiButton icon="mdi-plus" data-test="new-group" @click="openNew">New group</UiButton></template>
    <template #filters><UiInput id="group-search" v-model="q" label="Search" sr-only-label placeholder="Search groups" type="search" class="w-full md:max-w-sm" data-test="search" /></template>
    <UiAlert v-if="error && !dialog && !confirmDelete" kind="error" class="mb-3" data-test="error">{{ error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="rows" :columns="columns" caption="Groups" empty-title="No groups yet" :row-attrs="() => ({ 'data-test': 'group-row' })">
        <template #cell-name="{ row }">
          <RouterLink :to="{ name: 'admin-group', params: { id: row.id } }" class="link link-primary" data-test="group-name">{{ row.name }}</RouterLink>
          <div v-if="row.description" class="text-xs text-base-content/70">{{ row.description }}</div>
        </template>
        <template #cell-member_count="{ row }"><span data-test="member-count">{{ row.member_count }}</span></template>
        <template #actions="{ row }">
          <UiButton size="xs" variant="text" data-test="edit" @click="openEdit(row)">Rename</UiButton>
          <UiButton size="xs" variant="text" color="error" data-test="delete-group" @click="confirmDelete = row">Delete</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
    <UiRecordDrawer v-model="dialog" close-on-save :title="editing ? 'Rename group' : 'New group'" :schema="groupSchema" :fields="fields" :initial="editing ? { name: editing.name ?? '', description: editing.description ?? '' } : { name: '', description: '' }" :submit="submit" size="md" data-test="group-dialog" />
    <UiDialog :model-value="confirmDelete !== null" :title="'Delete ' + (confirmDelete?.name ?? '') + '?'" size="sm" data-test="delete-dialog" @update:model-value="confirmDelete = null">
      <p v-if="confirmDelete" class="text-sm" data-test="delete-summary">{{ confirmDelete.member_count }} member{{ confirmDelete.member_count === 1 ? '' : 's' }} will lose the roles this group grants: {{ (confirmDelete.roles ?? []).join(', ') || 'none' }}.</p>
      <UiAlert v-if="error" kind="error" class="mt-2" data-test="dialog-error">{{ error }}</UiAlert>
      <template #actions>
        <UiButton variant="text" @click="confirmDelete = null">Cancel</UiButton>
        <UiButton color="error" :loading="busy" data-test="confirm-delete" @click="remove">Delete group</UiButton>
      </template>
    </UiDialog>
  </UiPage>
</template>
