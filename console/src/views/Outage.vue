<script setup lang="ts">
import { useRouter } from 'vue-router'
import { useSession } from '@/stores/session'
import { useI18n } from '@/plugins/i18n'

const router = useRouter()
const session = useSession()
const { t } = useI18n()

async function retry(): Promise<void> {
  await session.load(true)
  if (session.status !== 'outage') await router.replace(session.signedIn ? '/' : { name: 'signin' })
}
</script>

<template>
  <v-card class="pa-6 text-center" role="alert" aria-live="assertive">
    <v-icon size="48" color="warning" class="mb-4">mdi-cloud-off-outline</v-icon>
    <h1 class="text-h5 mb-2">{{ t('outage.title') }}</h1>
    <p class="text-body-1 mb-6">{{ t('outage.body') }}</p>
    <v-btn color="primary" data-test="retry" @click="retry">{{ t('outage.retry') }}</v-btn>
  </v-card>
</template>
