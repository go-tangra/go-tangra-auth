<script setup lang="ts">
import { computed, watch } from 'vue'
import { UiForm, UiAlert, UiButton, UiDrawer } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { api } from '@/api/client'
import type { Role } from '@/composables/useRoles'
import { useGroups } from '@/stores/groups'
import { activateSchema, type ActivateResult } from '@/schemas/directory'
import RoleGroupPickers from './RoleGroupPickers.vue'

const props = defineProps<{ modelValue: boolean; roles: Role[]; users: { id: string; email: string }[] }>()
const emit = defineEmits<{ 'update:modelValue': [boolean]; activated: [ActivateResult] }>()
const groups = useGroups()
const form = useZodForm(activateSchema, {
  initial: { user_ids: [], role_ids: [], group_ids: [] },
  onSubmit: (v) => api<ActivateResult>('POST', '/api/v1/admin/users/activate', { user_ids: v.user_ids, role_ids: v.role_ids ?? [], ...(v.group_ids?.length ? { group_ids: v.group_ids } : {}) }),
  onSuccess: (result) => {
    emit('activated', result)
    emit('update:modelValue', false)
  },
})
const roleIds = computed({ get: () => (form.values.role_ids ?? []) as string[], set: (v: string[]) => { form.values.role_ids = v } })
const groupIds = computed({ get: () => (form.values.group_ids ?? []) as string[], set: (v: string[]) => { form.values.group_ids = v } })
watch(() => props.modelValue, (open) => {
  if (!open) return
  form.reset({ user_ids: props.users.map((u) => u.id), role_ids: [], group_ids: [] })
  if (!groups.loaded) void groups.load()
}, { immediate: true })
</script>

<template>
  <UiDrawer :model-value="modelValue" title="Activate users" size="md" data-test="activate-drawer" @update:model-value="!form.submitting.value && emit('update:modelValue', $event)">
    <UiForm :form="form">
      <div class="flex flex-col gap-3">
        <UiAlert v-for="(message, field) in form.errors.value" :key="field" kind="error">{{ message }}</UiAlert>
        <ul data-test="activate-targets"><li v-for="user in users" :key="user.id">{{ user.email }}</li></ul>
        <RoleGroupPickers v-model:role-ids="roleIds" v-model:group-ids="groupIds" prefix="activate" :roles="roles" :groups="groups.items" :disabled="form.submitting.value" />
        <p class="text-xs text-base-content/70">Each person receives an invitation link valid for 72 hours. Roles and groups apply when they accept.</p>
      </div>
    </UiForm>
    <template #actions>
      <UiButton variant="text" :disabled="form.submitting.value" @click="emit('update:modelValue', false)">Cancel</UiButton>
      <UiButton :loading="form.submitting.value" data-test="activate-send" @click="!form.submitting.value && form.submit()">Activate — send invitation</UiButton>
    </template>
  </UiDrawer>
</template>
