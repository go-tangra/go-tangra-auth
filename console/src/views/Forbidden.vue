<script setup lang="ts">
import { UiAlert } from '@freya/ui'
import { useI18n } from '@/plugins/i18n'
const { t } = useI18n()
</script>

<template>
  <UiAlert kind="warning" :title="t('forbidden.title')" />
</template>
