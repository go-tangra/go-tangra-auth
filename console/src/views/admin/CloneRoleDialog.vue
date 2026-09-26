<script setup lang="ts">
// Clone any role except owner into a new custom role (POST /admin/roles/{id}/clone).
// The slug follows the name until the administrator edits it.
import { ref, watch } from 'vue'
import { UiAlert, UiButton, UiDialog, UiInput } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import type { Role } from '@/composables/useRoles'
import { roleCloneSchema, suggestSlug } from '@/schemas'

const props = defineProps<{ source: Role | null }>()
const emit = defineEmits<{ close: []; cloned: [Role] }>()
const error = ref<string | null>(null)
const busy = ref(false)
const form = useZodForm(roleCloneSchema, {
  initial: { slug: '', display_name: '' },
  onSubmit: () => undefined,
  root: () => document.querySelector('[data-test="clone-dialog"]'),
})
watch(
  () => props.source,
  (r) => {
    if (!r) return
    const name = `${r.display_name || r.slug || ''} (copy)`
    error.value = null
    form.reset({ display_name: name, slug: suggestSlug(name) })
  },
  { immediate: true },
)
watch(
  () => form.values.display_name,
  (name, old) => {
    const slug = String(form.values.slug ?? '')
    if (slug === '' || slug === suggestSlug(String(old ?? ''))) form.values.slug = suggestSlug(String(name ?? ''))
  },
)
function describe(err: unknown): string {
  if (!(err instanceof ApiError)) return 'Could not clone the role.'
  if (err.reason === 'conflict') return 'A role with that slug already exists.'
  return reasonMessage(err.reason)
}
async function submit(): Promise<void> {
  const v = form.validate()
  if (!v || !props.source?.id) return
  busy.value = true
  error.value = null
  try {
    const created = await api<Role>('POST', `/api/v1/admin/roles/${encodeURIComponent(props.source.id)}/clone`, v)
    emit('cloned', created)
  } catch (err) {
    error.value = describe(err)
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <UiDialog :model-value="source !== null" :title="'Clone ' + (source?.display_name ?? '')" size="sm" data-test="clone-dialog" @update:model-value="!$event && emit('close')">
    <p class="mb-3 text-sm text-base-content/70">The copy is a custom role with the same permissions that you can edit.</p>
    <div class="flex flex-col gap-3">
      <UiInput v-bind="form.field('display_name')" id="clone-display-name" label="Name" required data-test="clone-name" />
      <UiInput v-bind="form.field('slug')" id="clone-slug" label="Slug" hint="lowercase letters, digits and dashes" required data-test="clone-slug" />
    </div>
    <UiAlert v-if="error" kind="error" class="mt-3" role="alert" data-test="clone-error">{{ error }}</UiAlert>
    <template #actions>
      <UiButton variant="text" @click="emit('close')">Cancel</UiButton>
      <UiButton :loading="busy" data-test="clone-confirm" @click="submit">Clone</UiButton>
    </template>
  </UiDialog>
</template>
