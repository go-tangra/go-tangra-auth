<script setup lang="ts">
import { UiCheckbox } from '@go-tangra/ui'
import { roleAssignable, roleLabel, type Role } from '@/composables/useRoles'
import type { Group } from '@/stores/groups'

defineProps<{ prefix: string; roles: Role[]; groups: Group[]; disabled?: boolean }>()
const roleIds = defineModel<string[]>('roleIds', { required: true })
const groupIds = defineModel<string[]>('groupIds', { required: true })
const RETIRED = 'No longer provided by its module; cannot be newly assigned'
function toggle(ids: string[], id: string, on: boolean): string[] {
  return on ? [...new Set([...ids, id])] : ids.filter((value) => value !== id)
}
</script>

<template>
  <fieldset :data-test="`${prefix}-roles`" :disabled="disabled">
    <legend class="mb-1 text-sm font-medium">Roles</legend>
    <UiCheckbox v-for="r in roles" :id="`${prefix}-role-${r.id}`" :key="r.id ?? ''" :model-value="roleIds.includes(r.id ?? '')" :label="roleLabel(r) + (r.retired ? ' (retired)' : '')" :disabled="!roleAssignable(r, roleIds)" :title="r.retired ? RETIRED : undefined" @update:model-value="roleIds = toggle(roleIds, r.id ?? '', $event)" />
  </fieldset>
  <fieldset :data-test="`${prefix}-groups`" :disabled="disabled">
    <legend class="mb-1 text-sm font-medium">Groups</legend>
    <p class="mb-1 text-xs text-base-content/70">Joined on acceptance; the person receives the groups' roles.</p>
    <UiCheckbox v-for="g in groups" :id="`${prefix}-group-${g.id}`" :key="g.id ?? ''" :model-value="groupIds.includes(g.id ?? '')" :label="g.name ?? ''" @update:model-value="groupIds = toggle(groupIds, g.id ?? '', $event)" />
    <p v-if="!groups.length" class="text-xs text-base-content/70">No groups yet.</p>
  </fieldset>
</template>
