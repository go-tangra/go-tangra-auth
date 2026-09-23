<script setup lang="ts">
// Invite a person: email, optional names, roles and groups. Console-unique
// (multi-select of roles/groups on top of the kit dialog).
import { computed, watch } from 'vue'
import { UiForm, UiInput, UiCheckbox, UiButton, UiDrawer } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { api } from '@/api/client'
import type { Role } from '@/composables/useRoles'
import { useGroups } from '@/stores/groups'
import { inviteSchema } from '@/schemas'

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
const roleIds = computed(() => (form.values.role_ids ?? []) as string[])
const groupIds = computed(() => (form.values.group_ids ?? []) as string[])
const toggle = (key: 'role_ids' | 'group_ids', id: string, on: unknown) => {
  const cur = (form.values[key] ?? []) as string[]
  form.values[key] = on ? [...new Set([...cur, id])] : cur.filter((x) => x !== id)
}
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
        <fieldset data-test="invite-roles">
          <legend class="mb-1 text-sm font-medium">Roles</legend>
          <UiCheckbox v-for="r in roles" :id="'invite-role-' + (r.id ?? '')" :key="r.id ?? ''" :model-value="roleIds.includes(r.id ?? '')" :label="r.display_name ?? r.slug ?? ''" @update:model-value="toggle('role_ids', r.id ?? '', $event)" />
        </fieldset>
        <fieldset data-test="invite-groups">
          <legend class="mb-1 text-sm font-medium">Groups</legend>
          <p class="mb-1 text-xs text-base-content/70">Joined on acceptance; the person receives the groups' roles.</p>
          <UiCheckbox v-for="g in groups.items" :id="'invite-group-' + (g.id ?? '')" :key="g.id ?? ''" :model-value="groupIds.includes(g.id ?? '')" :label="g.name ?? ''" @update:model-value="toggle('group_ids', g.id ?? '', $event)" />
          <p v-if="!groups.items.length" class="text-xs text-base-content/70">No groups yet.</p>
        </fieldset>
        <p class="text-xs text-base-content/70">The person receives a link valid for 72 hours. The response never reveals whether the address already has an account.</p>
      </div>
    </UiForm>
    <template #actions>
      <UiButton variant="text" @click="emit('update:modelValue', false)">Cancel</UiButton>
      <UiButton :loading="form.submitting.value" data-test="invite-send" @click="form.submit()">Send invitation</UiButton>
    </template>
  </UiDrawer>
</template>
