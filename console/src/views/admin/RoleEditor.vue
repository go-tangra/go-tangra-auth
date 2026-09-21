<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useRoles, type Role } from '@/composables/useRoles'

interface Permission {
  resource: string
  action: string
  description: string
}

const route = useRoute()
const router = useRouter()
const id = computed(() => (typeof route.params.id === 'string' ? route.params.id : ''))
const isNew = computed(() => id.value === '')
const { roles, load: loadRoles } = useRoles()
const catalogue = ref<Permission[]>([])
const slug = ref('')
const displayName = ref('')
const selected = ref<Set<string>>(new Set())
const error = ref<string | null>(null)
const busy = ref(false)
const builtin = ref(false)

const slugOk = computed(() => /^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/.test(slug.value) && !['owner', 'admin', 'member'].includes(slug.value))
const canSave = computed(() => !builtin.value && displayName.value.trim().length > 0 && (isNew.value ? slugOk.value : true) && !busy.value)

/** Permissions grouped by resource for the matrix. */
const groups = computed(() => {
  const m = new Map<string, Permission[]>()
  for (const p of catalogue.value) m.set(p.resource, [...(m.get(p.resource) ?? []), p])
  return [...m.entries()].map(([resource, perms]) => ({ resource, perms }))
})

function key(p: Permission): string {
  return `${p.resource}:${p.action}`
}
function toggle(p: Permission, on: boolean): void {
  const next = new Set(selected.value)
  if (on) next.add(key(p))
  else next.delete(key(p))
  selected.value = next
}

async function load(): Promise<void> {
  catalogue.value = await api<Permission[]>('GET', '/api/v1/admin/permissions')
  if (!isNew.value) {
    await loadRoles()
    const r: Role | undefined = roles.value.find((x) => x.id === id.value)
    if (!r) {
      error.value = reasonMessage('not_found')
      return
    }
    slug.value = r.slug ?? ''
    displayName.value = r.display_name ?? ''
    builtin.value = r.builtin ?? false
    selected.value = new Set(r.permissions ?? [])
  }
}

async function save(): Promise<void> {
  if (!canSave.value) return
  busy.value = true
  error.value = null
  const body = { slug: slug.value, display_name: displayName.value.trim(), permissions: [...selected.value] }
  try {
    if (isNew.value) await api('POST', '/api/v1/admin/roles', body)
    else await api('PUT', `/api/v1/admin/roles/${encodeURIComponent(id.value)}`, body)
    await router.push({ name: 'admin-roles' })
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not save the role.'
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <v-card data-test="role-editor">
    <v-card-title>{{ isNew ? 'New role' : 'Edit role' }}</v-card-title>
    <v-card-text>
      <v-alert v-if="builtin" type="info" variant="tonal" class="mb-4" data-test="builtin-lock">Built-in roles are defined by the platform and cannot be edited.</v-alert>
      <v-text-field v-model.trim="slug" label="Slug" :disabled="!isNew" hint="lowercase letters, digits and dashes" persistent-hint data-test="slug" />
      <v-text-field v-model="displayName" label="Name" :disabled="builtin" data-test="name" />
      <h3 class="text-subtitle-1 mt-4 mb-2">Permissions</h3>
      <p v-if="catalogue.length === 0" class="text-caption">No permissions have been registered by platform services yet.</p>
      <div v-for="g in groups" :key="g.resource" class="mb-3" data-test="group">
        <div class="text-subtitle-2">{{ g.resource }}</div>
        <v-checkbox
          v-for="p in g.perms"
          :key="key(p)"
          :model-value="selected.has(key(p))"
          :label="`${p.action}${p.description ? ' — ' + p.description : ''}`"
          :disabled="builtin"
          density="compact"
          hide-details
          data-test="perm"
          @update:model-value="toggle(p, $event === true)"
        />
      </div>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-4" role="alert" data-test="error">{{ error }}</v-alert>
    </v-card-text>
    <v-card-actions>
      <v-btn color="primary" :disabled="!canSave" :loading="busy" data-test="save" @click="save">Save</v-btn>
      <v-btn variant="text" :to="{ name: 'admin-roles' }">Cancel</v-btn>
    </v-card-actions>
  </v-card>
</template>
