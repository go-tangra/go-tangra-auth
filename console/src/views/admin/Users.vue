<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { api, ApiError } from '@/api/client'
import { reasonMessage, userStatuses } from '@/api/vocab'
import { useRoles } from '@/composables/useRoles'
import InviteDialog from './InviteDialog.vue'

export interface AdminUser {
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
const status = ref<(typeof userStatuses)[number] | null>(null)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const invite = ref(false)
const busy = ref(false)
const { roles, load: loadRoles } = useRoles()

async function load(): Promise<void> {
  error.value = null
  try {
    const page = await api<{ items: AdminUser[] }>('GET', '/api/v1/admin/users', undefined, { query: { q: q.value || undefined, status: status.value ?? undefined } })
    users.value = page.items
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
  busy.value = true
  error.value = null
  try {
    await api('POST', `/api/v1/admin/users/${encodeURIComponent(u.id)}/${op}`)
    notice.value = op === 'sessions/revoke' ? `${u.email} was signed out everywhere.` : `${u.email} is now ${op === 'deactivate' ? 'deactivated' : 'active'}.`
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
</script>

<template>
  <v-card>
    <v-card-title class="d-flex align-center">
      Users
      <v-spacer />
      <v-btn color="primary" prepend-icon="mdi-account-plus" data-test="invite-open" @click="invite = true">Invite</v-btn>
    </v-card-title>
    <v-card-text>
      <v-row dense>
        <v-col cols="12" md="6"><v-text-field v-model.trim="q" label="Search email or name" prepend-inner-icon="mdi-magnify" clearable data-test="search" /></v-col>
        <v-col cols="12" md="3"><v-select v-model="status" :items="[...userStatuses]" label="Status" clearable data-test="status" /></v-col>
      </v-row>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-2" data-test="error">{{ error }}</v-alert>
      <v-alert v-if="notice" type="success" variant="tonal" density="compact" class="mb-2" closable data-test="notice" @click:close="notice = null">{{ notice }}</v-alert>
      <v-table data-test="users">
        <thead>
          <tr>
            <th>Email</th>
            <th>Name</th>
            <th>Status</th>
            <th>Roles</th>
            <th>Last sign-in</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr v-for="u in users" :key="u.id" data-test="user-row">
            <td>
              <v-avatar size="28" class="mr-2" color="surface-variant" data-test="user-avatar">
                <v-img v-if="u.avatar_url" :src="u.avatar_url" :alt="u.display_name || u.email" cover />
                <span v-else class="text-caption" aria-hidden="true">{{ (u.display_name || u.email).slice(0, 1).toUpperCase() }}</span>
              </v-avatar>
              <router-link :to="{ name: 'admin-user', params: { id: u.id } }">{{ u.email }}</router-link>
            </td>
            <td data-test="user-name">{{ u.display_name }}</td>
            <td><v-chip size="small" :color="u.status === 'active' ? 'success' : u.status === 'deactivated' ? 'error' : 'warning'" data-test="status-chip">{{ u.status }}</v-chip></td>
            <td>{{ u.roles.join(', ') || '—' }}</td>
            <td>{{ u.last_signin_at ?? 'never' }}</td>
            <td class="text-right text-no-wrap">
              <v-btn v-if="u.status === 'active'" size="small" variant="text" :disabled="busy" data-test="signout" @click="act(u, 'sessions/revoke')">Sign out</v-btn>
              <v-btn v-if="u.status === 'active'" size="small" variant="text" color="error" :disabled="busy" data-test="deactivate" @click="act(u, 'deactivate')">Deactivate</v-btn>
              <v-btn v-if="u.status === 'deactivated'" size="small" variant="text" color="primary" :disabled="busy" data-test="reactivate" @click="act(u, 'reactivate')">Reactivate</v-btn>
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
    <InviteDialog v-model="invite" :roles="roles" @sent="notice = 'Invitation queued.'" />
  </v-card>
</template>
