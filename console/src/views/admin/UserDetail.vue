<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useRoles } from '@/composables/useRoles'
import { useGroups, type EffectiveRole, type UserGroupRef } from '@/stores/groups'
import ProfileForm from '@/components/ProfileForm.vue'
import type { AdminUser } from './Users.vue'

const route = useRoute()
const id = computed(() => String(route.params.id ?? ''))
const user = ref<AdminUser | null>(null)
const selected = ref<string[]>([])
const error = ref<string | null>(null)
const saved = ref(false)
const busy = ref(false)
const { roles, load: loadRoles } = useRoles()
const groups = useGroups()
const effective = ref<EffectiveRole[]>([])
const memberOf = ref<UserGroupRef[]>([])

async function loadEffective(): Promise<void> {
  try {
    effective.value = await groups.effectiveRoles(id.value)
    memberOf.value = await groups.userGroups(id.value)
  } catch (err) {
    if (!(err instanceof ApiError)) throw err
  }
}

async function load(): Promise<void> {
  const page = await api<{ items: AdminUser[] }>('GET', '/api/v1/admin/users')
  user.value = page.items.find((u) => u.id === id.value) ?? null
  if (!user.value) error.value = reasonMessage('not_found')
  await loadRoles()
  // Direct roles only are editable here; group roles show under "Effective roles".
  const direct = new Set(effective.value.filter((e) => e.sources?.some((s) => s.kind === 'direct')).map((e) => e.slug))
  await loadEffective()
  effective.value.forEach((e) => {
    if (e.sources?.some((s) => s.kind === 'direct')) direct.add(e.slug ?? '')
  })
  selected.value = roles.value.filter((r) => r.slug && (direct.size ? direct.has(r.slug) : user.value?.roles.includes(r.slug))).map((r) => r.id ?? '')
}

function sourceLabel(e: EffectiveRole): string {
  return (e.sources ?? []).map((s) => (s.kind === 'direct' ? 'direct' : `via ${s.group_name}`)).join(', ')
}

async function save(): Promise<void> {
  busy.value = true
  error.value = null
  saved.value = false
  try {
    const res = await api<{ roles: string[] }>('PUT', `/api/v1/admin/users/${encodeURIComponent(id.value)}/roles`, { role_ids: selected.value })
    if (user.value) user.value.roles = res.roles
    saved.value = true
    await loadEffective()
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not save roles.'
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <v-card v-if="user" data-test="user-detail">
    <v-card-title>{{ user.display_name || user.email }}</v-card-title>
    <v-card-subtitle>{{ user.email }} · {{ user.status }} · second factor {{ user.mfa_enabled ? 'enabled' : 'not enrolled' }}</v-card-subtitle>
    <v-card-text>
      <h3 class="text-subtitle-1 mb-2">Profile</h3>
      <ProfileForm :profile-path="`/api/v1/admin/users/${encodeURIComponent(id)}/profile`" :avatar-remove-path="`/api/v1/admin/users/${encodeURIComponent(id)}/avatar`" class="mb-6" @changed="(p) => { if (user) user.display_name = p.display_name ?? user.display_name }" />

      <h3 class="text-subtitle-1 mb-2">Roles</h3>
      <v-checkbox v-for="r in roles" :key="r.id ?? ''" v-model="selected" :value="r.id ?? ''" :label="`${r.display_name} (${(r.permissions ?? []).length} permissions)`" density="compact" hide-details data-test="role" />
      <p v-if="roles.length === 0" class="text-caption">No roles are defined yet.</p>

      <h3 class="text-subtitle-1 mt-6 mb-2">Effective roles</h3>
      <div data-test="effective-roles">
        <v-chip v-for="e in effective" :key="e.role_id ?? ''" class="mr-2 mb-2" size="small" data-test="effective-role">
          {{ e.slug }} <span class="text-caption ml-1">({{ sourceLabel(e) }})</span>
        </v-chip>
        <p v-if="effective.length === 0" class="text-caption">No roles held.</p>
      </div>

      <h3 class="text-subtitle-1 mt-4 mb-2">Groups</h3>
      <div data-test="user-groups">
        <v-chip v-for="g in memberOf" :key="g.id ?? ''" class="mr-2 mb-2" size="small" variant="outlined" :to="{ name: 'admin-group', params: { id: g.id ?? '' } }" data-test="user-group">{{ g.name }}</v-chip>
        <p v-if="memberOf.length === 0" class="text-caption">Not a member of any group.</p>
      </div>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-4" data-test="error">{{ error }}</v-alert>
      <v-alert v-if="saved" type="success" variant="tonal" density="compact" class="mt-4" data-test="saved">Roles updated.</v-alert>
    </v-card-text>
    <v-card-actions>
      <v-btn color="primary" :disabled="busy" :loading="busy" data-test="save" @click="save">Save roles</v-btn>
      <v-btn variant="text" :to="{ name: 'admin-users' }">Back</v-btn>
    </v-card-actions>
  </v-card>
  <v-alert v-else-if="error" type="warning" variant="tonal" data-test="error">{{ error }}</v-alert>
</template>
