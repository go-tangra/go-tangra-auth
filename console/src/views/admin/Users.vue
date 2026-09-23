<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiInput, UiSelect, UiDataTable, UiStatusChip, UiAvatar, useToast, useConfirm, type Column, type SelectOption } from '@freya/ui'
import { api, ApiError } from '@/api/client'
import { reasonMessage, userStatuses } from '@/api/vocab'
import { useRoles } from '@/composables/useRoles'
import InviteDialog from './InviteDialog.vue'

export interface AdminUser extends Record<string, unknown> {
  id: string
  email: string
  display_name: string
  status: string
  mfa_enabled: boolean
  roles: string[]
  last_signin_at: string | null
  first_name?: string
  last_name?: string
  avatar_url?: string
  groups?: { id: string; name: string }[]
}

const users = ref<AdminUser[]>([])
const q = ref('')
const status = ref<string | undefined>()
const error = ref<string | null>(null)
const invite = ref(false)
const busy = ref(false)
const toast = useToast()
const confirm = useConfirm()
const { roles, load: loadRoles } = useRoles()
const statusOptions: SelectOption[] = userStatuses.map((s) => ({ title: s, value: s }))

async function load(): Promise<void> {
  error.value = null
  try {
    users.value = (await api<{ items: AdminUser[] }>('GET', '/api/v1/admin/users', undefined, { query: { q: q.value || undefined, status: status.value || undefined } })).items
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load users.'
  }
}
let timer: number | undefined
watch([q, status], () => {
  window.clearTimeout(timer)
  timer = window.setTimeout(() => void load(), 250)
})
async function act(u: AdminUser, op: 'deactivate' | 'reactivate' | 'sessions/revoke'): Promise<void> {
  if (op === 'deactivate' && !(await confirm.ask({ title: `Deactivate ${u.email}?`, text: 'They are signed out everywhere and cannot sign in until reactivated.', danger: true, confirmLabel: 'Deactivate' }))) return
  busy.value = true
  error.value = null
  try {
    await api('POST', `/api/v1/admin/users/${encodeURIComponent(u.id)}/${op}`)
    toast.success(op === 'sessions/revoke' ? `${u.email} was signed out everywhere.` : `${u.email} is now ${op === 'deactivate' ? 'deactivated' : 'active'}.`)
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'The action failed.'
  } finally {
    busy.value = false
  }
}
onMounted(async () => {
  await Promise.all([load(), loadRoles()])
})
const columns: Column<AdminUser>[] = [
  { key: 'email', label: 'Email', sortable: true },
  { key: 'display_name', label: 'Name', sortable: true },
  { key: 'status', label: 'Status', width: 'sm' },
  { key: 'roles', label: 'Roles', format: (u) => u.roles.join(', '), hideOnStack: true },
  { key: 'last_signin_at', label: 'Last sign-in', format: (u) => u.last_signin_at ?? 'never', hideOnStack: true },
]
</script>

<template>
  <UiPage title="Users">
    <template #actions><UiButton icon="mdi-account-plus" data-test="invite-open" @click="invite = true">Invite</UiButton></template>
    <template #filters>
      <div class="grid w-full grid-cols-1 gap-2 md:grid-cols-12 md:items-end">
        <div class="md:col-span-6"><UiInput id="user-search" v-model="q" label="Search email or name" type="search" size="sm" data-test="search" /></div>
        <div class="md:col-span-3"><UiSelect id="user-status" v-model="status" label="Status" :options="statusOptions" size="sm" data-test="status" /></div>
      </div>
    </template>
    <UiAlert v-if="error" kind="error" class="mb-3" data-test="error">{{ error }}</UiAlert>
    <UiCard :padded="false">
      <UiDataTable :items="users" :columns="columns" caption="Users" empty-title="No users match" :row-attrs="() => ({ 'data-test': 'user-row' })" data-test="users">
        <template #cell-email="{ row }">
          <span class="inline-flex items-center gap-2">
            <span data-test="user-avatar"><UiAvatar :name="row.display_name || row.email" :src="row.avatar_url || undefined" size="sm" /></span>
            <RouterLink :to="{ name: 'admin-user', params: { id: row.id } }" class="link link-primary">{{ row.email }}</RouterLink>
          </span>
        </template>
        <template #cell-display_name="{ row }"><span data-test="user-name">{{ row.display_name }}</span></template>
        <template #cell-status="{ row }"><UiStatusChip :status="row.status" :colors="{ invited: 'warning', deactivated: 'error' }" data-test="status-chip" /></template>
        <template #actions="{ row }">
          <UiButton v-if="row.status === 'active'" size="xs" variant="text" :disabled="busy" data-test="signout" @click="act(row, 'sessions/revoke')">Sign out</UiButton>
          <UiButton v-if="row.status === 'active'" size="xs" variant="text" color="error" :disabled="busy" data-test="deactivate" @click="act(row, 'deactivate')">Deactivate</UiButton>
          <UiButton v-if="row.status === 'deactivated'" size="xs" variant="text" :disabled="busy" data-test="reactivate" @click="act(row, 'reactivate')">Reactivate</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
    <InviteDialog v-model="invite" :roles="roles" @sent="toast.success('Invitation queued.')" />
  </UiPage>
</template>
