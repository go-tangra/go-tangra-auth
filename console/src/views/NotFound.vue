<script setup lang="ts">
import { UiAlert } from '@go-tangra/ui'
import { useI18n } from '@/plugins/i18n'
const { t } = useI18n()
</script>

<template>
  <UiAlert kind="info" :title="t('notfound.title')" />
</template>
