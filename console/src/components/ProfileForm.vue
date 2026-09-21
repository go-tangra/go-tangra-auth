<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import type { components } from '@/api/schema'
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
const firstName = ref('')
const lastName = ref('')
const phone = ref('')
const displayName = ref('')
const avatarUrl = ref('')
const error = ref<string | null>(null)
const saved = ref(false)
const busy = ref(false)

const nameRule = (v: string) => v.length <= 100 || 'At most 100 characters'
const phoneRule = (v: string) => v.trim() === '' || /^\+?[0-9 ().-]{7,24}$/.test(v) || 'Use the international format, e.g. +385 91 123 4567'

async function load(): Promise<void> {
  try {
    const p = await api<Profile>('GET', props.profilePath)
    profile.value = p
    firstName.value = p.first_name ?? ''
    lastName.value = p.last_name ?? ''
    phone.value = p.phone ?? ''
    displayName.value = p.display_name ?? ''
    avatarUrl.value = p.avatar_url ?? ''
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load the profile.'
  }
}

async function save(): Promise<void> {
  if (nameRule(firstName.value) !== true || nameRule(lastName.value) !== true || phoneRule(phone.value) !== true) return
  busy.value = true
  error.value = null
  saved.value = false
  try {
    const body: Record<string, string> = { first_name: firstName.value, last_name: lastName.value, phone: phone.value }
    // The display name is sent only when the person typed one that differs
    // from the derived value; empty returns to derivation.
    const derived = `${firstName.value.trim()} ${lastName.value.trim()}`.trim()
    if (displayName.value.trim() !== derived) body.display_name = displayName.value.trim()
    const p = await api<Profile>('PUT', props.profilePath, body)
    profile.value = p
    phone.value = p.phone ?? ''
    displayName.value = p.display_name ?? ''
    saved.value = true
    emit('changed', p)
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not save the profile.'
  } finally {
    busy.value = false
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
    <AvatarEditor v-model="avatarUrl" :name="displayName" :upload-path="avatarUploadPath" :remove-path="avatarRemovePath" class="mb-4" @changed="avatarChanged" />
    <v-form @submit.prevent="save">
      <v-row dense>
        <v-col cols="12" sm="6"><v-text-field v-model="firstName" label="First name" :rules="[nameRule]" maxlength="100" autocomplete="given-name" data-test="first-name" /></v-col>
        <v-col cols="12" sm="6"><v-text-field v-model="lastName" label="Last name" :rules="[nameRule]" maxlength="100" autocomplete="family-name" data-test="last-name" /></v-col>
        <v-col cols="12" sm="6"><v-text-field v-model="phone" label="Phone" :rules="[phoneRule]" placeholder="+385 91 123 4567" autocomplete="tel" data-test="phone" /></v-col>
        <v-col cols="12" sm="6"><v-text-field v-model="displayName" label="Display name" hint="Shown across the platform; leave as is to use your first and last name" persistent-hint maxlength="100" data-test="display-name" /></v-col>
      </v-row>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-4" data-test="profile-error">{{ error }}</v-alert>
      <v-alert v-if="saved" type="success" variant="tonal" density="compact" class="mb-4" data-test="profile-saved">Profile saved.</v-alert>
      <v-btn type="submit" color="primary" :disabled="busy" :loading="busy" data-test="profile-save">Save profile</v-btn>
    </v-form>
  </div>
</template>
