<script setup lang="ts">
import { computed, onMounted, onBeforeUnmount, ref, watch } from 'vue'
import { RouterLink } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiInput, UiSelect, UiDataTable, UiStatusChip, UiAvatar, UiCheckbox, useToast, useConfirm, type Column, type SelectOption } from '@freya/ui'
import type { components } from '@/api/schema'
import { api, ApiError } from '@/api/client'
import { reasonMessage, userStatuses } from '@/api/vocab'
import { useRoles } from '@/composables/useRoles'
import InviteDialog from './InviteDialog.vue'
import ActivateDrawer from './ActivateDrawer.vue'
import type { ActivateResult } from '@/schemas/directory'

export interface AdminUser extends Record<string, unknown> {
  invitation_id?: string | null
  directory?: components['schemas']['User']['directory']
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
const selected = ref<string[]>([])
const activationOpen = ref(false)
const targets = ref<AdminUser[]>([])
const result = ref<ActivateResult | null>(null)
const resultEmails = ref<Record<string, string>>({})
const imported = computed(() => users.value.filter((u) => u.status === 'imported'))
const failures = computed(() => result.value?.items.filter((item) => item.outcome === 'failed') ?? [])
const invitedCount = computed(() => result.value?.items.filter((item) => item.outcome === 'invited').length ?? 0)
function select(u: AdminUser, on: boolean): void {
  if (u.status !== 'imported' || busy.value) return
  selected.value = on ? [...new Set([...selected.value, u.id])].slice(0, 100) : selected.value.filter((id) => id !== u.id)
}
function openActivation(rows: AdminUser[]): void {
  targets.value = rows.filter((u) => u.status === 'imported').slice(0, 100)
  if (!targets.value.length) return
  result.value = null
  activationOpen.value = true
}
async function activated(value: ActivateResult): Promise<void> {
  resultEmails.value = Object.fromEntries(targets.value.map((u) => [u.id, u.email]))
  result.value = value
  selected.value = []
  await load()
}
async function resend(u: AdminUser): Promise<void> {
  if (busy.value || u.status !== 'invited' || !u.invitation_id) return
  busy.value = true
  error.value = null
  try {
    await api('POST', `/api/v1/admin/invitations/${encodeURIComponent(u.invitation_id)}/resend`)
    toast.success(`Invitation queued for ${u.email}.`)
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'The action failed.'
  } finally { busy.value = false }
}
const toast = useToast()
const confirm = useConfirm()
const { roles, load: loadRoles } = useRoles()
const statusOptions: SelectOption[] = userStatuses.map((s) => ({ title: s, value: s }))

async function load(): Promise<void> {
  selected.value = []
  error.value = null
  try {
    users.value = (await api<{ items: AdminUser[] }>('GET', '/api/v1/admin/users', undefined, { query: { q: q.value || undefined, status: status.value || undefined } })).items
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load users.'
  }
}
let timer: number | undefined
watch([q, status], () => {
  selected.value = []
  window.clearTimeout(timer)
  timer = window.setTimeout(() => void load(), 250)
})
onBeforeUnmount(() => window.clearTimeout(timer))
async function act(u: AdminUser, op: 'deactivate' | 'reactivate' | 'sessions/revoke' | 'remove-imported'): Promise<void> {
  if (busy.value) return
  if (op === 'remove-imported' && !(await confirm.ask({ title: `Remove ${u.email}?`, text: 'This deletes the imported user and their directory link. No invitation will be sent.', danger: true, confirmLabel: 'Remove' }))) return
  if (op === 'deactivate' && !(await confirm.ask({ title: `Deactivate ${u.email}?`, text: 'They are signed out everywhere and cannot sign in until reactivated.', danger: true, confirmLabel: 'Deactivate' }))) return
  busy.value = true
  error.value = null
  try {
    await api('POST', `/api/v1/admin/users/${encodeURIComponent(u.id)}/${op}`)
    toast.success(op === 'remove-imported' ? `${u.email} was removed.` : op === 'sessions/revoke' ? `${u.email} was signed out everywhere.` : `${u.email} is now ${op === 'deactivate' ? 'deactivated' : 'active'}.`)
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
  { key: 'selection', label: 'Select', width: 'sm' },
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
    <div class="mb-3 flex items-center gap-3">
      <UiButton variant="text" data-test="select-all" :disabled="busy || !imported.length" @click="selected = selected.length ? [] : imported.slice(0, 100).map((u) => u.id)">{{ selected.length ? 'Clear selection' : 'Select imported users (up to 100)' }}</UiButton>
      <UiButton data-test="activate-selected" :disabled="busy || !selected.length" @click="openActivation(users.filter((u) => selected.includes(u.id)))">Activate selected ({{ selected.length }})</UiButton>
    </div>
    <div v-if="result" class="mb-3" role="status">
      <p data-test="activate-summary">Activation finished: {{ invitedCount }} invited, {{ failures.length }} failed.</p>
      <ul><li v-for="item in failures" :key="item.user_id" data-test="activate-failure">{{ resultEmails[item.user_id] ?? item.user_id }}: {{ reasonMessage(item.reason ?? 'generic') }}</li></ul>
    </div>
    <UiCard :padded="false">
      <UiDataTable :items="users" :columns="columns" caption="Users" empty-title="No users match" :row-attrs="() => ({ 'data-test': 'user-row' })" data-test="users">
        <template #cell-selection="{ row }">
          <UiCheckbox :id="`activate-select-${row.id}`" :label="`Select ${row.email}`" :model-value="selected.includes(row.id)" :disabled="busy || row.status !== 'imported' || (selected.length >= 100 && !selected.includes(row.id))" @update:model-value="select(row, $event)" />
        </template>
        <template #cell-email="{ row }">
          <span class="inline-flex items-center gap-2">
            <span data-test="user-avatar"><UiAvatar :name="row.display_name || row.email" :src="row.avatar_url || undefined" size="sm" /></span>
            <RouterLink :to="{ name: 'admin-user', params: { id: row.id } }" class="link link-primary">{{ row.email }}</RouterLink>
          </span>
        </template>
        <template #cell-display_name="{ row }"><span data-test="user-name">{{ row.display_name }}</span></template>
        <template #cell-status="{ row }"><UiStatusChip :status="row.status" :colors="{ invited: 'warning', deactivated: 'error', imported: 'neutral' }" data-test="status-chip" /><span v-if="row.directory" data-test="origin" :title="`Imported from ${row.directory.connection_name} at ${row.directory.last_imported_at}`" class="ml-2 text-xs text-base-content/70">{{ row.directory.connection_name }}</span></template>
        <template #actions="{ row }">
          <UiButton v-if="row.status === 'imported'" size="xs" variant="text" :disabled="busy" data-test="activate" @click="openActivation([row])">Activate</UiButton>
          <UiButton v-if="row.status === 'imported'" size="xs" variant="text" color="error" :disabled="busy" data-test="remove-imported" @click="act(row, 'remove-imported')">Remove</UiButton>
          <UiButton v-if="row.status === 'invited' && row.invitation_id" size="xs" variant="text" :disabled="busy" data-test="resend" @click="resend(row)">Resend</UiButton>
          <UiButton v-if="row.status === 'active'" size="xs" variant="text" :disabled="busy" data-test="signout" @click="act(row, 'sessions/revoke')">Sign out</UiButton>
          <UiButton v-if="row.status === 'active'" size="xs" variant="text" color="error" :disabled="busy" data-test="deactivate" @click="act(row, 'deactivate')">Deactivate</UiButton>
          <UiButton v-if="row.status === 'deactivated'" size="xs" variant="text" :disabled="busy" data-test="reactivate" @click="act(row, 'reactivate')">Reactivate</UiButton>
        </template>
      </UiDataTable>
    </UiCard>
    <ActivateDrawer v-model="activationOpen" :roles="roles" :users="targets" @activated="activated" />
    <InviteDialog v-model="invite" :roles="roles" @sent="toast.success('Invitation queued.')" />
  </UiPage>
</template>
