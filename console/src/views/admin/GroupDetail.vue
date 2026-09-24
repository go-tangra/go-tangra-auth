<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { RouterLink, useRoute, useRouter } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiCheckbox, UiCombobox, UiDataTable, UiAvatar, useToast, type Column, type SelectOption } from '@go-tangra/ui'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useRoles } from '@/composables/useRoles'
import { useGroups, type Group, type GroupMember } from '@/stores/groups'
import type { AdminUser } from './Users.vue'

const route = useRoute()
const router = useRouter()
const toast = useToast()
const id = computed(() => String(route.params.id ?? ''))
const groups = useGroups()
const group = ref<Group | null>(null)
const members = ref<GroupMember[]>([])
const selectedRoles = ref<string[]>([])
const candidates = ref<SelectOption[]>([])
const picked = ref('')
const error = ref<string | null>(null)
const busy = ref(false)
const { roles, load: loadRoles } = useRoles()

async function load(): Promise<void> {
  error.value = null
  try {
    group.value = await groups.get(id.value)
    members.value = await groups.members(id.value)
    await loadRoles()
    selectedRoles.value = roles.value.filter((r) => r.slug && group.value?.roles?.includes(r.slug)).map((r) => r.id ?? '')
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load the group.'
  }
}
async function searchUsers(q: string): Promise<void> {
  if (!q) {
    candidates.value = []
    return
  }
  try {
    const page = await api<{ items: AdminUser[] }>('GET', '/api/v1/admin/users', undefined, { query: { q } })
    const present = new Set(members.value.map((m) => m.user_id))
    candidates.value = page.items.filter((u) => !present.has(u.id)).map((u) => ({ title: u.email + (u.display_name ? ' · ' + u.display_name : ''), value: u.id }))
  } catch (err) {
    if (!(err instanceof ApiError)) throw err
  }
}
async function addMember(): Promise<void> {
  if (!picked.value) return
  busy.value = true
  error.value = null
  try {
    const n = await groups.addMembers(id.value, [picked.value])
    toast.success(n === 1 ? 'Member added.' : 'Already a member.')
    picked.value = ''
    candidates.value = []
    members.value = await groups.members(id.value)
    group.value = await groups.get(id.value)
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not add the member.'
  } finally {
    busy.value = false
  }
}
async function removeMember(userId: string): Promise<void> {
  busy.value = true
  error.value = null
  try {
    await groups.removeMember(id.value, userId)
    members.value = members.value.filter((m) => m.user_id !== userId)
    if (group.value) group.value.member_count = members.value.length
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not remove the member.'
  } finally {
    busy.value = false
  }
}
async function saveRoles(): Promise<void> {
  busy.value = true
  error.value = null
  try {
    const slugs = await groups.setRoles(id.value, selectedRoles.value)
    if (group.value) group.value.roles = slugs
    toast.success('Roles updated for every member.')
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not save roles.'
  } finally {
    busy.value = false
  }
}
const toggleRole = (rid: string, on: unknown) => (selectedRoles.value = on ? [...new Set([...selectedRoles.value, rid])] : selectedRoles.value.filter((x) => x !== rid))
onMounted(load)
type Row = GroupMember & Record<string, unknown> & { id: string }
const rows = computed<Row[]>(() => members.value.map((m) => ({ ...m, id: m.user_id ?? '' })))
const columns: Column<Row>[] = [
  { key: 'display_name', label: 'Person', format: (m) => m.display_name || m.email || '' },
  { key: 'status', label: 'Status', width: 'sm' },
  { key: 'added_at', label: 'Added', format: (m) => (m.added_at ? new Date(m.added_at).toLocaleDateString() : ''), hideOnStack: true },
]
</script>

<template>
  <UiPage v-if="group" :title="group.name ?? ''" :subtitle="`${group.description || 'No description'} · ${group.member_count} member${group.member_count === 1 ? '' : 's'}`" data-test="group-detail">
    <template #actions><UiButton variant="text" icon="mdi-arrow-left" @click="router.push({ name: 'admin-groups' })">Back to groups</UiButton></template>
    <span class="sr-only" data-test="group-name">{{ group.name }}</span>
    <UiAlert v-if="error" kind="error" class="mb-3" data-test="error">{{ error }}</UiAlert>
    <div class="grid grid-cols-1 gap-4 lg:grid-cols-12">
      <UiCard title="Roles granted to members" class="lg:col-span-4">
        <div data-test="group-roles">
          <UiCheckbox v-for="r in roles.filter((x) => x.slug !== 'owner')" :id="'group-role-' + (r.id ?? '')" :key="r.id ?? ''" :model-value="selectedRoles.includes(r.id ?? '')" :label="`${r.display_name} (${r.slug})`" data-test="group-role" @update:model-value="toggleRole(r.id ?? '', $event)" />
        </div>
        <UiButton class="mt-3" :loading="busy" data-test="save-roles" @click="saveRoles">Save roles</UiButton>
      </UiCard>
      <UiCard title="Members" class="lg:col-span-8" :padded="false">
        <div class="flex flex-wrap items-end gap-2 px-4 pt-2 pb-3">
          <UiCombobox id="add-member" v-model="picked" label="Add a person by email or name" :options="candidates" placeholder="Type to search" class="grow" data-test="add-member" @search="searchUsers" />
          <UiButton :disabled="!picked || busy" data-test="add-member-confirm" @click="addMember">Add</UiButton>
        </div>
        <UiDataTable :items="rows" :columns="columns" caption="Members" empty-title="No members yet" :row-attrs="() => ({ 'data-test': 'member-row' })">
          <template #cell-display_name="{ row }">
            <span class="inline-flex items-center gap-2">
              <UiAvatar :name="row.display_name || row.email || '?'" :src="row.avatar_url || undefined" size="sm" />
              <span><RouterLink :to="{ name: 'admin-user', params: { id: row.id } }" class="link link-primary">{{ row.display_name || row.email }}</RouterLink><span class="block text-xs text-base-content/70">{{ row.email }}</span></span>
            </span>
          </template>
          <template #actions="{ row }"><UiButton size="xs" variant="text" color="error" :disabled="busy" data-test="remove-member" @click="removeMember(row.id)">Remove</UiButton></template>
        </UiDataTable>
      </UiCard>
    </div>
  </UiPage>
  <UiAlert v-else-if="error" kind="warning" data-test="error">{{ error }}</UiAlert>
</template>
