<script setup lang="ts">
import { useI18n } from '@/plugins/i18n'
const { t } = useI18n()
</script>

<template>
  <v-alert type="info" variant="tonal" :title="t('notfound.title')" />
</template>
