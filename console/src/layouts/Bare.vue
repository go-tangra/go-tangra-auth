<script setup lang="ts">
// Centered card layout for unauthenticated flows: the page colour behind one
// 400px card, the platform theme applied through data-theme.
import { UiToast, UiConfirm, useTheme } from '@freya/ui'
useTheme()
</script>

<template>
  <main class="bg-base-200 flex min-h-dvh items-center justify-center px-4 py-10 sm:px-6">
    <div class="w-full sm:max-w-md [&_.card]:shadow-md [&_.card-body]:gap-6 [&_.card-body]:p-6 lg:[&_.card-body]:p-8"><slot /></div>
    <UiToast />
    <UiConfirm />
  </main>
</template>
