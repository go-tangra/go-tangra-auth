<script setup lang="ts">
import { computed, onMounted, ref, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiForm, UiInput, UiCheckbox, UiSection } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { roleClonable, roleLocked, roleOrigin, useRoles, type Role } from '@/composables/useRoles'
import { isLegacyPermission, roleSchema } from '@/schemas'
import CloneRoleDialog from './CloneRoleDialog.vue'

/** One row of GET /admin/permissions (contracts/http.md, feature 019). */
interface Permission {
  ref: string
  module: string
  module_display_name: string
  resource: string
  action: string
  description: string
  grantable: boolean
  legacy: boolean
}
interface ResourceGroup {
  resource: string
  perms: Permission[]
}
interface ModuleSection {
  module: string
  title: string
  groups: ResourceGroup[]
  grantable: string[]
}
const NOT_HELD = 'You do not hold this permission'

const route = useRoute()
const router = useRouter()
const id = computed(() => (typeof route.params.id === 'string' ? route.params.id : ''))
const isNew = computed(() => id.value === '')
const { roles, load: loadRoles } = useRoles()
const catalogue = ref<Permission[]>([])
const loadError = ref<string | null>(null)
const role = ref<Role | null>(null)
const cloning = ref<Role | null>(null)
const origin = computed(() => (role.value ? roleOrigin(role.value) : 'custom'))
const readOnly = computed(() => role.value !== null && roleLocked(role.value))

const form = useZodForm(roleSchema, {
  initial: { slug: '', display_name: '', permissions: [] },
  onSubmit: async (v) => {
    if (isNew.value) await api('POST', '/api/v1/admin/roles', v)
    else await api('PUT', `/api/v1/admin/roles/${encodeURIComponent(id.value)}`, v)
  },
  onSuccess: () => router.push({ name: 'admin-roles' }),
})
const selected = computed(() => (form.values.permissions ?? []) as string[])
const byText = (a: string, b: string) => a.localeCompare(b)

/** Module sections (by display name), each with resource sub-groups (by resource, then action). */
const sections = computed<ModuleSection[]>(() => {
  const mods = new Map<string, { title: string; perms: Permission[] }>()
  for (const p of catalogue.value) {
    if (p.legacy) continue
    const m = mods.get(p.module) ?? { title: p.module_display_name || p.module, perms: [] }
    m.perms.push(p)
    mods.set(p.module, m)
  }
  return [...mods.entries()]
    .map(([module, m]) => {
      const res = new Map<string, Permission[]>()
      for (const p of m.perms) res.set(p.resource, [...(res.get(p.resource) ?? []), p])
      const groups = [...res.entries()].sort(([a], [b]) => byText(a, b)).map(([resource, perms]) => ({ resource, perms: perms.sort((a, b) => byText(a.action, b.action)) }))
      return { module, title: m.title, groups, grantable: m.perms.filter((p) => p.grantable).map((p) => p.ref) }
    })
    .sort((a, b) => byText(a.title, b.title) || byText(a.module, b.module))
})
/** Pre-module grants the role still holds: shown read-only and kept on save. */
const legacyHeld = computed(() => {
  const known = new Map(catalogue.value.filter((p) => p.legacy).map((p) => [p.ref, p.description]))
  return selected.value.filter(isLegacyPermission).map((ref) => ({ ref, label: known.get(ref) ? `${ref} — ${known.get(ref)}` : ref }))
})
const label = (p: Permission) => `${p.action}${p.description ? ' — ' + p.description : ''}`
function toggle(p: Permission, on: unknown): void {
  form.values.permissions = on ? [...new Set([...selected.value, p.ref])] : selected.value.filter((k) => k !== p.ref)
}
/** "Select all" / "Clear" for a module: only permissions the actor may grant change. */
function selectAll(s: ModuleSection, on: boolean): void {
  const refs = new Set(s.grantable)
  form.values.permissions = on ? [...new Set([...selected.value, ...refs])] : selected.value.filter((k) => !refs.has(k))
}
/** Accepts servers that predate module-scoped permissions (no ref / module fields). */
function normalise(p: Partial<Permission> & { resource: string; action: string }): Permission {
  const legacy = p.legacy ?? !p.module
  return {
    ref: p.ref ?? (p.module ? `${p.module}:${p.resource}:${p.action}` : `${p.resource}:${p.action}`),
    module: p.module ?? '',
    module_display_name: p.module_display_name ?? (legacy ? 'Before modules' : (p.module ?? '')),
    resource: p.resource,
    action: p.action,
    description: p.description ?? '',
    grantable: p.grantable ?? true,
    legacy,
  }
}
async function load(): Promise<void> {
  loadError.value = null
  role.value = null
  try {
    catalogue.value = (await api<Permission[]>('GET', '/api/v1/admin/permissions')).map(normalise)
    if (isNew.value) {
      form.reset({ slug: '', display_name: '', permissions: [] })
      return
    }
    await loadRoles()
    const r: Role | undefined = roles.value.find((x) => x.id === id.value)
    if (!r) {
      loadError.value = reasonMessage('not_found')
      return
    }
    role.value = r
    form.reset({ slug: r.slug ?? '', display_name: r.display_name ?? '', permissions: [...(r.permissions ?? [])] })
  } catch (err) {
    loadError.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load the role.'
  }
}
function cloned(r: Role): void {
  cloning.value = null
  if (r.id) void router.push({ name: 'admin-role', params: { id: r.id } })
}
onMounted(load)
// The editor stays mounted when a clone opens the new role's page.
watch(id, () => void load())
</script>

<template>
  <UiPage :title="isNew ? 'New role' : readOnly ? 'View role' : 'Edit role'" data-test="role-editor">
    <template v-if="role && roleClonable(role)" #actions>
      <UiButton variant="soft" icon="mdi-content-copy" data-test="clone" @click="cloning = role">Clone</UiButton>
    </template>
    <UiCard>
      <UiAlert v-if="origin === 'builtin'" kind="info" class="mb-4" data-test="builtin-lock">Built-in roles are defined by the platform and cannot be edited.<template v-if="role && roleClonable(role)"> Clone it to start a custom role from its permissions.</template></UiAlert>
      <UiAlert v-else-if="origin === 'module'" kind="info" class="mb-4" data-test="module-lock">
        Provided by the {{ role?.module_display_name || role?.module }} module. Module roles are managed by their module; clone it to customise.
        <template v-if="role?.retired"> No longer provided by {{ role?.module_display_name || role?.module }}; kept for existing assignments.</template>
      </UiAlert>
      <UiAlert v-if="loadError" kind="error" class="mb-4" role="alert" data-test="error">{{ loadError }}</UiAlert>
      <UiForm :form="form">
        <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
          <UiInput v-bind="form.field('slug')" label="Slug" :disabled="!isNew" hint="lowercase letters, digits and dashes" required data-test="slug" />
          <UiInput v-bind="form.field('display_name')" label="Name" :disabled="readOnly" required data-test="name" />
        </div>
        <UiSection title="Permissions" class="mt-4">
          <p v-if="catalogue.length === 0" class="text-xs text-base-content/70">No permissions have been registered by platform services yet.</p>
          <section v-for="s in sections" :key="s.module" class="mb-4 rounded-box border border-base-content/10 p-3" :data-module="s.module" data-test="module">
            <div class="mb-2 flex flex-wrap items-center justify-between gap-2">
              <h3 class="text-sm font-semibold">{{ s.title }}</h3>
              <div v-if="!readOnly" class="flex gap-1">
                <UiButton size="xs" variant="text" :disabled="s.grantable.length === 0" data-test="select-all" @click="selectAll(s, true)">Select all</UiButton>
                <UiButton size="xs" variant="text" :disabled="s.grantable.length === 0" data-test="clear" @click="selectAll(s, false)">Clear</UiButton>
              </div>
            </div>
            <div v-for="g in s.groups" :key="g.resource" class="mb-2" data-test="group">
              <h4 class="mb-1 text-xs font-medium text-base-content/70">{{ g.resource }}</h4>
              <UiCheckbox v-for="p in g.perms" :id="'perm-' + p.ref" :key="p.ref" :model-value="selected.includes(p.ref)" :label="label(p)" :disabled="readOnly || !p.grantable" :title="p.grantable ? undefined : NOT_HELD" data-test="perm" @update:model-value="toggle(p, $event)" />
            </div>
          </section>
          <section v-if="legacyHeld.length" class="mb-4 rounded-box border border-dashed border-base-content/20 p-3" data-test="legacy">
            <h3 class="mb-1 text-sm font-semibold">Before modules</h3>
            <p class="mb-2 text-xs text-base-content/70">Grants from before permissions belonged to modules. They are kept until the platform removes them and cannot be granted again.</p>
            <UiCheckbox v-for="l in legacyHeld" :id="'perm-legacy-' + l.ref" :key="l.ref" :model-value="true" :label="l.label" disabled data-test="legacy-perm" />
          </section>
        </UiSection>
      </UiForm>
      <div class="mt-4 flex gap-2">
        <UiButton :disabled="readOnly" :loading="form.submitting.value" data-test="save" @click="form.submit()">Save</UiButton>
        <UiButton variant="text" @click="router.push({ name: 'admin-roles' })">Cancel</UiButton>
      </div>
    </UiCard>
    <CloneRoleDialog :source="cloning" @close="cloning = null" @cloned="cloned" />
  </UiPage>
</template>
