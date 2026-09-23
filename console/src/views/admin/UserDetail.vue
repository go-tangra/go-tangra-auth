<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiCheckbox, UiBadge, UiSection } from '@freya/ui'
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
  await loadEffective()
  const direct = new Set(effective.value.filter((e) => e.sources?.some((s) => s.kind === 'direct')).map((e) => e.slug ?? ''))
  selected.value = roles.value.filter((r) => r.slug && (direct.size ? direct.has(r.slug) : user.value?.roles.includes(r.slug))).map((r) => r.id ?? '')
}
const toggle = (rid: string, on: unknown) => (selected.value = on ? [...new Set([...selected.value, rid])] : selected.value.filter((x) => x !== rid))
const sourceLabel = (e: EffectiveRole) => (e.sources ?? []).map((s) => (s.kind === 'direct' ? 'direct' : `via ${s.group_name}`)).join(', ')
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
  <UiPage v-if="user" :title="user.display_name || user.email" :subtitle="`${user.email} · ${user.status} · second factor ${user.mfa_enabled ? 'enabled' : 'not enrolled'}`" data-test="user-detail">
    <template #actions><UiButton variant="text" icon="mdi-arrow-left" @click="$router.push({ name: 'admin-users' })">Back</UiButton></template>
    <UiCard title="Profile" class="mb-4">
      <ProfileForm :profile-path="`/api/v1/admin/users/${encodeURIComponent(id)}/profile`" :avatar-remove-path="`/api/v1/admin/users/${encodeURIComponent(id)}/avatar`" @changed="(p) => { if (user) user.display_name = p.display_name ?? user.display_name }" />
    </UiCard>
    <UiCard title="Roles">
      <UiSection title="Direct roles">
        <UiCheckbox v-for="r in roles" :id="'role-' + (r.id ?? '')" :key="r.id ?? ''" :model-value="selected.includes(r.id ?? '')" :label="`${r.display_name} (${(r.permissions ?? []).length} permissions)`" data-test="role" @update:model-value="toggle(r.id ?? '', $event)" />
        <p v-if="roles.length === 0" class="text-xs text-base-content/70">No roles are defined yet.</p>
      </UiSection>
      <UiSection title="Effective roles">
        <div class="flex flex-wrap gap-1" data-test="effective-roles">
          <UiBadge v-for="e in effective" :key="e.role_id ?? ''" size="md" data-test="effective-role">{{ e.slug }} <span class="ms-1 text-xs text-base-content/70">({{ sourceLabel(e) }})</span></UiBadge>
          <p v-if="effective.length === 0" class="text-xs text-base-content/70">No roles held.</p>
        </div>
      </UiSection>
      <UiSection title="Groups">
        <div class="flex flex-wrap gap-1" data-test="user-groups">
          <RouterLink v-for="g in memberOf" :key="g.id ?? ''" :to="{ name: 'admin-group', params: { id: g.id ?? '' } }" class="badge badge-outline" data-test="user-group">{{ g.name }}</RouterLink>
          <p v-if="memberOf.length === 0" class="text-xs text-base-content/70">Not a member of any group.</p>
        </div>
      </UiSection>
      <UiAlert v-if="error" kind="error" class="mt-4" data-test="error">{{ error }}</UiAlert>
      <UiAlert v-if="saved" kind="success" class="mt-4" data-test="saved">Roles updated.</UiAlert>
      <UiButton class="mt-4" :loading="busy" data-test="save" @click="save">Save roles</UiButton>
    </UiCard>
  </UiPage>
  <UiAlert v-else-if="error" kind="warning" data-test="error">{{ error }}</UiAlert>
</template>
