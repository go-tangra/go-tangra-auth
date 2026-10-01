<script setup lang="ts">
// The organisation's password rules as a live checklist under a new-password
// form. Advisory only: the server validates again on submit and, when it
// refuses, `refused` names the rule it reported.
import { computed } from 'vue'
import { UiIcon } from '@go-tangra/ui'
import type { RuleKey, RuleState } from '@/password/rules'

const props = defineProps<{
  id: string
  checklist: RuleState[]
  refused?: RuleKey | undefined
}>()

const met = computed(() => props.checklist.filter((r) => r.met).length)
const status = computed(() =>
  props.refused ? `The password was refused: ${props.checklist.find((r) => r.key === props.refused)?.label.toLowerCase() ?? 'policy'}.` : `${met.value} of ${props.checklist.length} password requirements met.`,
)

function state(r: RuleState): 'refused' | 'met' | 'pending' {
  if (r.key === props.refused) return 'refused'
  return r.met ? 'met' : 'pending'
}
const icon = { refused: 'mdi-alert-circle-outline', met: 'mdi-check-circle-outline', pending: 'mdi-circle-outline' } as const
const tone = { refused: 'text-error', met: 'text-success', pending: 'text-base-content/70' } as const
const srState = { refused: 'refused by the server', met: 'met', pending: 'not met yet' } as const
</script>

<template>
  <div :id="id" class="rounded-box border border-base-content/10 bg-base-200/50 p-3" data-test="pw-rules">
    <p :id="`${id}-title`" class="mb-1 text-sm font-medium">Password requirements</p>
    <ul :aria-labelledby="`${id}-title`" class="flex flex-col gap-1 text-sm">
      <li v-for="r in checklist" :key="r.key" :class="['flex items-center gap-2', tone[state(r)]]" :data-rule="r.key" :data-state="state(r)">
        <UiIcon :name="icon[state(r)]" size="sm" />
        <span>{{ r.label }}<span class="sr-only"> ({{ srState[state(r)] }})</span></span>
      </li>
    </ul>
    <p class="sr-only" aria-live="polite" aria-atomic="true" data-test="pw-rules-status">{{ status }}</p>
  </div>
</template>
