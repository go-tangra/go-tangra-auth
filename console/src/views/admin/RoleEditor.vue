<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiForm, UiInput, UiCheckbox, UiSection } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useRoles, type Role } from '@/composables/useRoles'
import { roleSchema } from '@/schemas'

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
const loadError = ref<string | null>(null)
const builtin = ref(false)

const form = useZodForm(roleSchema, {
  initial: { slug: '', display_name: '', permissions: [] },
  onSubmit: async (v) => {
    if (isNew.value) await api('POST', '/api/v1/admin/roles', v)
    else await api('PUT', `/api/v1/admin/roles/${encodeURIComponent(id.value)}`, v)
  },
  onSuccess: () => router.push({ name: 'admin-roles' }),
})
const selected = computed(() => (form.values.permissions ?? []) as string[])
/** Permissions grouped by resource for the matrix. */
const groups = computed(() => {
  const m = new Map<string, Permission[]>()
  for (const p of catalogue.value) m.set(p.resource, [...(m.get(p.resource) ?? []), p])
  return [...m.entries()].map(([resource, perms]) => ({ resource, perms }))
})
const key = (p: Permission) => `${p.resource}:${p.action}`
function toggle(p: Permission, on: unknown): void {
  form.values.permissions = on ? [...new Set([...selected.value, key(p)])] : selected.value.filter((k) => k !== key(p))
}
async function load(): Promise<void> {
  try {
    catalogue.value = await api<Permission[]>('GET', '/api/v1/admin/permissions')
    if (!isNew.value) {
      await loadRoles()
      const r: Role | undefined = roles.value.find((x) => x.id === id.value)
      if (!r) {
        loadError.value = reasonMessage('not_found')
        return
      }
      builtin.value = r.builtin ?? false
      form.reset({ slug: r.slug ?? '', display_name: r.display_name ?? '', permissions: [...(r.permissions ?? [])] })
    }
  } catch (err) {
    loadError.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load the role.'
  }
}
onMounted(load)
</script>

<template>
  <UiPage :title="isNew ? 'New role' : 'Edit role'" data-test="role-editor">
    <UiCard>
      <UiAlert v-if="builtin" kind="info" class="mb-4" data-test="builtin-lock">Built-in roles are defined by the platform and cannot be edited.</UiAlert>
      <UiAlert v-if="loadError" kind="error" class="mb-4" role="alert" data-test="error">{{ loadError }}</UiAlert>
      <UiForm :form="form">
        <div class="grid grid-cols-1 gap-3 md:grid-cols-2">
          <UiInput v-bind="form.field('slug')" label="Slug" :disabled="!isNew" hint="lowercase letters, digits and dashes" required data-test="slug" />
          <UiInput v-bind="form.field('display_name')" label="Name" :disabled="builtin" required data-test="name" />
        </div>
        <UiSection title="Permissions" class="mt-4">
          <p v-if="catalogue.length === 0" class="text-xs text-base-content/70">No permissions have been registered by platform services yet.</p>
          <div v-for="g in groups" :key="g.resource" class="mb-3" data-test="group">
            <h3 class="mb-1 text-sm font-medium">{{ g.resource }}</h3>
            <UiCheckbox v-for="p in g.perms" :id="'perm-' + key(p)" :key="key(p)" :model-value="selected.includes(key(p))" :label="`${p.action}${p.description ? ' — ' + p.description : ''}`" :disabled="builtin" data-test="perm" @update:model-value="toggle(p, $event)" />
          </div>
        </UiSection>
      </UiForm>
      <div class="mt-4 flex gap-2">
        <UiButton :disabled="builtin" :loading="form.submitting.value" data-test="save" @click="form.submit()">Save</UiButton>
        <UiButton variant="text" @click="router.push({ name: 'admin-roles' })">Cancel</UiButton>
      </div>
    </UiCard>
  </UiPage>
</template>
