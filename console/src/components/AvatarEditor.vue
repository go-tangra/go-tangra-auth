<script setup lang="ts">
// Avatar upload/remove (raw PUT of the picture). Console-unique: the auth
// service stores the 512×512 picture and serves it from the profile.
import { ref } from 'vue'
import { UiAvatar, UiButton, UiAlert } from '@go-tangra/ui'
import { api, ApiError, upload } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { avatarSchema, AVATAR_TYPES } from '@/schemas'

const props = withDefaults(defineProps<{
  /** Current avatar address (empty for none). */
  modelValue: string
  /** Placeholder text (initials) when there is no picture. */
  name?: string
  /** Upload endpoint; empty means the editor can only remove (admin mode). */
  uploadPath?: string
  /** Remove endpoint. */
  removePath: string
}>(), { name: '', uploadPath: '' })
const emit = defineEmits<{ 'update:modelValue': [value: string]; changed: [] }>()
const error = ref<string | null>(null)
const busy = ref(false)
const preview = ref<string | null>(null)
const input = ref<HTMLInputElement | null>(null)

function pick(): void {
  input.value?.click()
}
async function onFile(ev: Event): Promise<void> {
  const file = (ev.target as HTMLInputElement).files?.[0]
  if (!file) return
  error.value = null
  const checked = avatarSchema.safeParse(file)
  if (!checked.success) {
    error.value = checked.error.issues[0]?.message ?? reasonMessage('unsupported_type')
    if (input.value) input.value.value = ''
    return
  }
  busy.value = true
  const url = URL.createObjectURL(file)
  preview.value = url
  try {
    const res = await upload<{ avatar_url: string }>(props.uploadPath, file)
    emit('update:modelValue', res.avatar_url)
    emit('changed')
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not upload the picture.'
  } finally {
    busy.value = false
    preview.value = null
    URL.revokeObjectURL(url)
    if (input.value) input.value.value = ''
  }
}
async function remove(): Promise<void> {
  error.value = null
  busy.value = true
  try {
    await api('DELETE', props.removePath)
    emit('update:modelValue', '')
    emit('changed')
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not remove the picture.'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="flex items-center gap-4" data-test="avatar-editor">
    <span data-test="avatar-preview"><UiAvatar :name="name || '?'" :src="preview || modelValue || undefined" size="lg" /></span>
    <div>
      <input ref="input" type="file" :accept="AVATAR_TYPES.join(',')" class="sr-only" aria-label="Choose a picture" data-test="avatar-file" @change="onFile">
      <div class="flex flex-wrap gap-2">
        <UiButton v-if="uploadPath" size="sm" variant="soft" :loading="busy" :disabled="busy" data-test="avatar-upload" @click="pick">{{ modelValue ? 'Change picture' : 'Upload picture' }}</UiButton>
        <UiButton v-if="modelValue" size="sm" variant="text" :disabled="busy" data-test="avatar-remove" @click="remove">Remove</UiButton>
      </div>
      <p class="mt-1 text-xs text-base-content/70">PNG, JPEG or WebP, up to 2 MB. Stored as a 512 × 512 picture.</p>
      <UiAlert v-if="error" kind="error" class="mt-2" data-test="avatar-error">{{ error }}</UiAlert>
    </div>
  </div>
</template>
