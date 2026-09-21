<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useRoles } from '@/composables/useRoles'
import { useGroups, type Group, type GroupMember } from '@/stores/groups'
import type { AdminUser } from './Users.vue'

const route = useRoute()
const id = computed(() => String(route.params.id ?? ''))
const groups = useGroups()
const group = ref<Group | null>(null)
const members = ref<GroupMember[]>([])
const selectedRoles = ref<string[]>([])
const candidates = ref<AdminUser[]>([])
const picked = ref<string | null>(null)
const search = ref('')
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
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
  search.value = q
  if (!q) {
    candidates.value = []
    return
  }
  try {
    const page = await api<{ items: AdminUser[] }>('GET', '/api/v1/admin/users', undefined, { query: { q } })
    const present = new Set(members.value.map((m) => m.user_id))
    candidates.value = page.items.filter((u) => !present.has(u.id))
  } catch (err) {
    if (!(err instanceof ApiError)) throw err
  }
}

async function addMember(): Promise<void> {
  if (!picked.value) return
  busy.value = true
  error.value = null
  notice.value = null
  try {
    const n = await groups.addMembers(id.value, [picked.value])
    notice.value = n === 1 ? 'Member added.' : 'Already a member.'
    picked.value = null
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
  notice.value = null
  try {
    const slugs = await groups.setRoles(id.value, selectedRoles.value)
    if (group.value) group.value.roles = slugs
    notice.value = 'Roles updated for every member.'
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not save roles.'
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <v-card v-if="group" data-test="group-detail">
    <v-card-title data-test="group-name">{{ group.name }}</v-card-title>
    <v-card-subtitle>{{ group.description || 'No description' }} · {{ group.member_count }} member{{ group.member_count === 1 ? '' : 's' }}</v-card-subtitle>
    <v-card-text>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-4" data-test="error">{{ error }}</v-alert>
      <v-alert v-if="notice" type="success" variant="tonal" density="compact" class="mb-4" data-test="notice">{{ notice }}</v-alert>

      <h3 class="text-subtitle-1 mb-2">Roles granted to members</h3>
      <div data-test="group-roles">
        <v-checkbox v-for="r in roles.filter((x) => x.slug !== 'owner')" :key="r.id ?? ''" v-model="selectedRoles" :value="r.id ?? ''" :label="`${r.display_name} (${r.slug})`" density="compact" hide-details data-test="group-role" />
      </div>
      <v-btn color="primary" class="mt-2" :disabled="busy" :loading="busy" data-test="save-roles" @click="saveRoles">Save roles</v-btn>

      <h3 class="text-subtitle-1 mt-6 mb-2">Members</h3>
      <div class="d-flex align-center ga-2">
        <v-autocomplete
          v-model="picked"
          :items="candidates"
          item-title="email"
          item-value="id"
          label="Add a person by email or name"
          density="compact"
          hide-details
          no-filter
          data-test="add-member"
          @update:search="searchUsers"
        >
          <template #item="{ props: p, item }">
            <v-list-item v-bind="p" :subtitle="candidates.find((c) => c.id === (item as unknown as { value: string }).value)?.display_name ?? ''" />
          </template>
        </v-autocomplete>
        <v-btn color="primary" :disabled="!picked || busy" data-test="add-member-confirm" @click="addMember">Add</v-btn>
      </div>
      <v-table class="mt-2">
        <thead>
          <tr>
            <th>Person</th>
            <th>Status</th>
            <th>Added</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr v-for="m in members" :key="m.user_id" data-test="member-row">
            <td>
              <v-avatar size="24" class="mr-2" color="surface-variant">
                <v-img v-if="m.avatar_url" :src="m.avatar_url" :alt="m.display_name || m.email" />
                <span v-else class="text-caption">{{ (m.display_name || m.email || '?').slice(0, 1).toUpperCase() }}</span>
              </v-avatar>
              <router-link :to="{ name: 'admin-user', params: { id: m.user_id } }">{{ m.display_name || m.email }}</router-link>
              <div class="text-caption">{{ m.email }}</div>
            </td>
            <td>{{ m.status }}</td>
            <td>{{ m.added_at ? new Date(m.added_at).toLocaleDateString() : '' }}</td>
            <td class="text-right">
              <v-btn size="small" variant="text" color="error" :disabled="busy" data-test="remove-member" @click="removeMember(m.user_id ?? '')">Remove</v-btn>
            </td>
          </tr>
          <tr v-if="members.length === 0">
            <td colspan="4" class="text-caption">No members yet.</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
    <v-card-actions>
      <v-btn variant="text" :to="{ name: 'admin-groups' }">Back to groups</v-btn>
    </v-card-actions>
  </v-card>
  <v-alert v-else-if="error" type="warning" variant="tonal" data-test="error">{{ error }}</v-alert>
</template>
