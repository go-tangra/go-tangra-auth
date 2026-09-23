<script setup lang="ts">
import { useRouter } from 'vue-router'
import { UiCard, UiIcon, UiButton } from '@freya/ui'
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
  <UiCard role="alert" aria-live="assertive" class="text-center">
    <UiIcon name="mdi-cloud-off-outline" size="xl" class="mx-auto mb-3 text-warning" />
    <h1 class="mb-1 text-xl font-semibold">{{ t('outage.title') }}</h1>
    <p class="mb-5 text-base-content/70">{{ t('outage.body') }}</p>
    <UiButton data-test="retry" @click="retry">{{ t('outage.retry') }}</UiButton>
  </UiCard>
</template>
