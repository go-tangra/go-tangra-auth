<script setup lang="ts">
// Profile (names, phone, display name) with the avatar editor; used by the
// person's own account page and by the admin user page (different endpoints).
import { onMounted, ref } from 'vue'
import { UiForm, UiInput, UiButton, UiAlert } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import type { components } from '@/api/schema'
import { profileSchema } from '@/schemas'
import AvatarEditor from './AvatarEditor.vue'

type Profile = components['schemas']['Profile']
const props = withDefaults(defineProps<{
  /** Profile endpoint (GET/PUT). */
  profilePath: string
  /** Avatar endpoint for uploads (empty = remove only). */
  avatarUploadPath?: string
  /** Avatar endpoint for removal. */
  avatarRemovePath: string
}>(), { avatarUploadPath: '' })
const emit = defineEmits<{ changed: [profile: Profile] }>()
const profile = ref<Profile | null>(null)
const avatarUrl = ref('')
const loadError = ref<string | null>(null)
const saved = ref(false)

const form = useZodForm(profileSchema, {
  initial: { first_name: '', last_name: '', phone: '', display_name: '' },
  onSubmit: async (v) => {
    saved.value = false
    const body: Record<string, string> = { first_name: v.first_name ?? '', last_name: v.last_name ?? '', phone: v.phone ?? '' }
    // The display name is sent only when the person typed one that differs
    // from the derived value; empty returns to derivation.
    const derived = `${v.first_name ?? ''} ${v.last_name ?? ''}`.trim()
    if ((v.display_name ?? '') !== derived) body.display_name = v.display_name ?? ''
    const p = await api<Profile>('PUT', props.profilePath, body)
    apply(p)
    saved.value = true
    emit('changed', p)
  },
})
function apply(p: Profile): void {
  profile.value = p
  avatarUrl.value = p.avatar_url ?? ''
  form.reset({ first_name: p.first_name ?? '', last_name: p.last_name ?? '', phone: p.phone ?? '', display_name: p.display_name ?? '' })
}
async function load(): Promise<void> {
  try {
    apply(await api<Profile>('GET', props.profilePath))
  } catch (err) {
    loadError.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load the profile.'
  }
}
async function avatarChanged(): Promise<void> {
  await load()
  if (profile.value) emit('changed', profile.value)
}
onMounted(load)
</script>

<template>
  <div data-test="profile-form">
    <AvatarEditor v-model="avatarUrl" :name="String(form.values.display_name ?? '')" :upload-path="avatarUploadPath" :remove-path="avatarRemovePath" class="mb-4" @changed="avatarChanged" />
    <UiForm :form="form">
      <div class="grid grid-cols-1 gap-3 sm:grid-cols-2">
        <UiInput v-bind="form.field('first_name')" label="First name" autocomplete="given-name" data-test="first-name" />
        <UiInput v-bind="form.field('last_name')" label="Last name" autocomplete="family-name" data-test="last-name" />
        <UiInput v-bind="form.field('phone')" label="Phone" placeholder="+385 91 123 4567" autocomplete="tel" data-test="phone" />
        <UiInput v-bind="form.field('display_name')" label="Display name" hint="Shown across the platform; leave as is to use your first and last name" data-test="display-name" />
      </div>
      <UiAlert v-if="loadError" kind="error" class="mt-3" data-test="profile-error">{{ loadError }}</UiAlert>
      <UiAlert v-if="saved" kind="success" class="mt-3" data-test="profile-saved">Profile saved.</UiAlert>
      <UiButton type="submit" class="mt-3" :loading="form.submitting.value" data-test="profile-save">Save profile</UiButton>
    </UiForm>
  </div>
</template>
