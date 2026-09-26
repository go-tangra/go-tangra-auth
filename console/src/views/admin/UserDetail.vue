<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiCheckbox, UiBadge, UiSection, useConfirm, useToast } from '@go-tangra/ui'
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
const confirm = useConfirm()
const toast = useToast()

// Second factors (feature 018): methods only, never key material.
interface UserMfa {
  totp: boolean
  keys: { name: string; created_at: string; last_used_at: string | null; flagged: boolean }[]
  recovery_codes_left: number
}
const mfa = ref<UserMfa | null>(null)
const mfaError = ref<string | null>(null)
const mfaBusy = ref(false)
const mfaPath = computed(() => `/api/v1/admin/users/${encodeURIComponent(id.value)}/mfa`)
const fmt = (at: string) => new Date(at).toLocaleString()
async function loadMfa(): Promise<void> {
  try {
    const r = await api<Partial<UserMfa>>('GET', mfaPath.value)
    // Normalise: an older or partial answer must not break the page.
    mfa.value = { totp: !!r.totp, keys: Array.isArray(r.keys) ? r.keys : [], recovery_codes_left: r.recovery_codes_left ?? 0 }
  } catch (err) {
    mfa.value = null
    if (err instanceof ApiError && err.status !== 404) mfaError.value = reasonMessage(err.reason)
  }
}
async function resetMfa(): Promise<void> {
  const who = user.value?.email ?? 'this user'
  if (!(await confirm.ask({ title: `Reset the second factors of ${who}?`, text: 'Their authenticator app, security keys and recovery codes are removed and they are signed out everywhere. They must set up a second factor again.', danger: true, confirmLabel: 'Reset second factors' }))) return
  mfaBusy.value = true
  mfaError.value = null
  try {
    await api('POST', `${mfaPath.value}/reset`)
    toast.success(`The second factors of ${who} were reset.`)
    await loadMfa()
  } catch (err) {
    mfaError.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not reset the second factors.'
  } finally {
    mfaBusy.value = false
  }
}

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
  await Promise.all([loadEffective(), loadMfa()])
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
    <UiCard title="Second factors" class="mb-4" data-test="user-mfa">
      <template v-if="mfa">
        <p v-if="!mfa.totp && mfa.keys.length === 0" class="text-sm text-base-content/70" data-test="mfa-none">No second factor is set up.</p>
        <template v-else>
          <p class="text-sm">Authenticator app: <strong>{{ mfa.totp ? 'yes' : 'no' }}</strong></p>
          <p class="text-sm">Security keys: <strong>{{ mfa.keys.length }}</strong></p>
          <ul v-if="mfa.keys.length" class="ms-4 list-disc text-sm" data-test="user-keys">
            <li v-for="k in mfa.keys" :key="k.name">
              {{ k.name }}
              <span class="text-xs text-base-content/70">· added <time :datetime="k.created_at">{{ fmt(k.created_at) }}</time> ·
                <template v-if="k.last_used_at">last used <time :datetime="k.last_used_at">{{ fmt(k.last_used_at) }}</time></template><template v-else>never used</template></span>
              <UiBadge v-if="k.flagged" color="error" class="ms-1">Possibly cloned</UiBadge>
            </li>
          </ul>
          <p class="text-sm">Unused recovery codes: <strong>{{ mfa.recovery_codes_left }}</strong></p>
          <UiButton class="mt-4" variant="outline" color="error" icon="mdi-shield-off-outline" :loading="mfaBusy" data-test="mfa-reset" @click="resetMfa">Reset second factors</UiButton>
        </template>
      </template>
      <UiAlert v-if="mfaError" kind="error" class="mt-4" data-test="mfa-error">{{ mfaError }}</UiAlert>
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
