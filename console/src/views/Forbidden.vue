<script setup lang="ts">
import { useI18n } from '@/plugins/i18n'
const { t } = useI18n()
</script>

<template>
  <v-alert type="warning" variant="tonal" :title="t('forbidden.title')" />
</template>
