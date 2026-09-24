<script setup lang="ts">
// Invite a person: email, optional names, roles and groups. Console-unique
// (multi-select of roles/groups on top of the kit dialog).
import { computed, watch } from 'vue'
import { UiForm, UiInput, UiButton, UiDrawer } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { api } from '@/api/client'
import type { Role } from '@/composables/useRoles'
import { useGroups } from '@/stores/groups'
import { inviteSchema } from '@/schemas'
import RoleGroupPickers from './RoleGroupPickers.vue'

const props = defineProps<{ modelValue: boolean; roles: Role[] }>()
const emit = defineEmits<{ 'update:modelValue': [boolean]; sent: [] }>()
const groups = useGroups()
const form = useZodForm(inviteSchema, {
  initial: { email: '', first_name: '', last_name: '', role_ids: [], group_ids: [] },
  onSubmit: (v) => api('POST', '/api/v1/admin/invitations', { email: v.email, role_ids: v.role_ids, ...(v.group_ids.length ? { group_ids: v.group_ids } : {}), ...(v.first_name ? { first_name: v.first_name } : {}), ...(v.last_name ? { last_name: v.last_name } : {}) }),
  onSuccess: () => {
    emit('sent')
    emit('update:modelValue', false)
  },
})
const roleIds = computed({ get: () => (form.values.role_ids ?? []) as string[], set: (v: string[]) => { form.values.role_ids = v } })
const groupIds = computed({ get: () => (form.values.group_ids ?? []) as string[], set: (v: string[]) => { form.values.group_ids = v } })
watch(() => props.modelValue, (open) => {
  if (!open) return
  form.reset({ email: '', first_name: '', last_name: '', role_ids: [], group_ids: [] })
  if (!groups.loaded) void groups.load()
}, { immediate: true })
</script>

<template>
  <UiDrawer :model-value="modelValue" title="Invite a user" size="md" data-test="invite-dialog" @update:model-value="emit('update:modelValue', $event)">
    <UiForm :form="form">
      <div class="flex flex-col gap-3">
        <UiInput v-bind="form.field('email')" label="Email" type="email" required data-test="invite-email" />
        <div class="grid grid-cols-2 gap-2">
          <UiInput v-bind="form.field('first_name')" label="First name" data-test="invite-first-name" />
          <UiInput v-bind="form.field('last_name')" label="Last name" data-test="invite-last-name" />
        </div>
        <RoleGroupPickers v-model:role-ids="roleIds" v-model:group-ids="groupIds" prefix="invite" :roles="roles" :groups="groups.items" :disabled="form.submitting.value" />
        <p class="text-xs text-base-content/70">The person receives a link valid for 72 hours. The response never reveals whether the address already has an account.</p>
      </div>
    </UiForm>
    <template #actions>
      <UiButton variant="text" @click="emit('update:modelValue', false)">Cancel</UiButton>
      <UiButton :loading="form.submitting.value" data-test="invite-send" @click="form.submit()">Send invitation</UiButton>
    </template>
  </UiDrawer>
</template>
