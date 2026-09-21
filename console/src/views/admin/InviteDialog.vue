<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import type { Role } from '@/composables/useRoles'
import { useGroups } from '@/stores/groups'

const props = defineProps<{ modelValue: boolean; roles: Role[] }>()
const emit = defineEmits<{ 'update:modelValue': [boolean]; sent: [] }>()

const groups = useGroups()
const email = ref('')
const roleIds = ref<string[]>([])
const groupIds = ref<string[]>([])
const firstName = ref('')
const lastName = ref('')
const error = ref<string | null>(null)
const busy = ref(false)
const emailOk = computed(() => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.value))

watch(
  () => props.modelValue,
  (open) => {
    if (open) {
      email.value = ''
      roleIds.value = []
      groupIds.value = []
      firstName.value = ''
      lastName.value = ''
      error.value = null
      if (!groups.loaded) void groups.load()
    }
  },
)

async function send(): Promise<void> {
  if (!emailOk.value) return
  busy.value = true
  error.value = null
  try {
    const body: Record<string, unknown> = { email: email.value, role_ids: roleIds.value }
    if (groupIds.value.length) body.group_ids = groupIds.value
    if (firstName.value.trim()) body.first_name = firstName.value.trim()
    if (lastName.value.trim()) body.last_name = lastName.value.trim()
    await api('POST', '/api/v1/admin/invitations', body)
    emit('sent')
    emit('update:modelValue', false)
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'The invitation could not be queued.'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <v-dialog :model-value="modelValue" max-width="480" @update:model-value="emit('update:modelValue', $event)">
    <v-card data-test="invite-dialog">
      <v-card-title>Invite a user</v-card-title>
      <v-card-text>
        <v-text-field v-model.trim="email" label="Email" type="email" data-test="invite-email" autofocus />
        <v-row dense>
          <v-col cols="6"><v-text-field v-model="firstName" label="First name" maxlength="100" data-test="invite-first-name" /></v-col>
          <v-col cols="6"><v-text-field v-model="lastName" label="Last name" maxlength="100" data-test="invite-last-name" /></v-col>
        </v-row>
        <v-select v-model="roleIds" :items="roles" item-title="display_name" item-value="id" label="Roles" multiple chips data-test="invite-roles" />
        <v-select v-model="groupIds" :items="groups.items" item-title="name" item-value="id" label="Groups" multiple chips hint="Joined on acceptance; the person receives the groups' roles" persistent-hint data-test="invite-groups" />
        <v-alert v-if="error" type="error" variant="tonal" density="compact" data-test="invite-error">{{ error }}</v-alert>
        <p class="text-caption mt-2">The person receives a link valid for 72 hours. The response never reveals whether the address already has an account.</p>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="emit('update:modelValue', false)">Cancel</v-btn>
        <v-btn color="primary" :disabled="!emailOk || busy" :loading="busy" data-test="invite-send" @click="send">Send invitation</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
