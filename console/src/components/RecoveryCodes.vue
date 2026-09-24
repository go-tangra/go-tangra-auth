<script setup lang="ts">
// One-time recovery codes: legible (monospace, two columns) and copyable as a
// block. Console-unique: shown once after enrolment or regeneration.
import { UiCopyButton } from '@go-tangra/ui'
defineProps<{ codes: string[] }>()
</script>

<template>
  <div class="rounded-box border border-base-300 bg-base-200 p-3">
    <ul class="grid grid-cols-2 gap-x-4 gap-y-1 font-mono text-sm" data-test="recovery-codes">
      <li v-for="c in codes" :key="c" class="select-all">{{ c }}</li>
    </ul>
    <div class="mt-2 flex justify-end"><UiCopyButton :value="codes.join('\n')" label="Copy all codes" size="xs" /></div>
  </div>
</template>
