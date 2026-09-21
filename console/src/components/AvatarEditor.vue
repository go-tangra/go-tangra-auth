<script setup lang="ts">
import { computed, ref } from 'vue'
import { api, ApiError, upload } from '@/api/client'
import { reasonMessage } from '@/api/vocab'

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

const MAX_BYTES = 2 * 1024 * 1024
const ACCEPT = ['image/png', 'image/jpeg', 'image/webp']
const error = ref<string | null>(null)
const busy = ref(false)
const preview = ref<string | null>(null)
const input = ref<HTMLInputElement | null>(null)

const initials = computed(() =>
  props.name
    .split(/\s+/)
    .filter(Boolean)
    .slice(0, 2)
    .map((w) => w[0]!.toUpperCase())
    .join(''),
)

function pick(): void {
  input.value?.click()
}

async function onFile(ev: Event): Promise<void> {
  const file = (ev.target as HTMLInputElement).files?.[0]
  if (!file) return
  error.value = null
  if (!ACCEPT.includes(file.type)) {
    error.value = reasonMessage('unsupported_type')
    return
  }
  if (file.size > MAX_BYTES) {
    error.value = reasonMessage('body_too_large')
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
  <div class="d-flex align-center ga-4" data-test="avatar-editor">
    <v-avatar size="72" color="surface-variant" data-test="avatar-preview">
      <v-img v-if="preview || modelValue" :src="preview || modelValue" alt="Avatar" cover />
      <span v-else class="text-h6" aria-hidden="true">{{ initials || '?' }}</span>
    </v-avatar>
    <div>
      <input ref="input" type="file" :accept="ACCEPT.join(',')" class="d-none" data-test="avatar-file" @change="onFile">
      <v-btn v-if="uploadPath" size="small" color="primary" variant="tonal" :loading="busy" :disabled="busy" data-test="avatar-upload" @click="pick">
        {{ modelValue ? 'Change picture' : 'Upload picture' }}
      </v-btn>
      <v-btn v-if="modelValue" size="small" variant="text" class="ml-2" :disabled="busy" data-test="avatar-remove" @click="remove">Remove</v-btn>
      <div class="text-caption mt-1">PNG, JPEG or WebP, up to 2 MB. Stored as a 512 × 512 picture.</div>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mt-2" data-test="avatar-error">{{ error }}</v-alert>
    </div>
  </div>
</template>
