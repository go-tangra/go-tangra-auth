<script setup lang="ts">
import { computed } from 'vue'
import { useRouter } from 'vue-router'
import { UiAppShell, UiNavDrawer, UiButton, UiToast, UiConfirm, useTheme, type NavGroup } from '@freya/ui'
import { useSession } from '@/stores/session'
import { useI18n } from '@/plugins/i18n'
import type { MessageKey } from '@/plugins/i18n'

const session = useSession()
const router = useRouter()
const { t } = useI18n()
const theme = useTheme()
const dark = computed(() => theme.theme.value === 'freya-dark')

interface NavItem {
  key: MessageKey
  to: string
  icon: string
  roles?: string[]
  operator?: boolean
}
// Navigation is filtered by role; the server enforces the same rules.
const all: NavItem[] = [
  { key: 'nav.home', to: '/', icon: 'mdi-home-outline' },
  { key: 'nav.sessions', to: '/sessions', icon: 'mdi-devices' },
  { key: 'nav.security', to: '/security', icon: 'mdi-shield-key-outline' },
  { key: 'nav.users', to: '/admin/users', icon: 'mdi-account-multiple-outline', roles: ['owner', 'admin'] },
  { key: 'nav.groups', to: '/admin/groups', icon: 'mdi-account-group-outline', roles: ['owner', 'admin'] },
  { key: 'nav.roles', to: '/admin/roles', icon: 'mdi-account-key-outline', roles: ['owner', 'admin'] },
  { key: 'nav.policy', to: '/admin/policy', icon: 'mdi-file-cog-outline', roles: ['owner', 'admin'] },
  { key: 'nav.audit', to: '/admin/audit', icon: 'mdi-clipboard-text-clock-outline', roles: ['owner', 'admin', 'auditor'] },
  { key: 'nav.clients', to: '/admin/clients', icon: 'mdi-application-brackets-outline', roles: ['owner', 'admin'] },
  { key: 'nav.tenants', to: '/operator/tenants', icon: 'mdi-domain', operator: true },
]
const groups = computed<NavGroup[]>(() => [
  { items: all.filter((i) => (i.operator ? session.operator : true) && (i.roles ? session.hasAnyRole(i.roles) : true)).map((i) => ({ title: t(i.key), path: i.to, icon: i.icon, exact: i.to === '/', testId: 'nav-' + i.key.replace('nav.', '') })) },
])

async function signOut(): Promise<void> {
  await session.signOut()
  await router.push({ name: 'signin' })
}
</script>

<template>
  <UiAppShell :title="session.tenant?.display_name ?? t('app.title')">
    <template #app-bar>
      <UiButton variant="text" size="sm" icon-only :icon="dark ? 'mdi-weather-sunny' : 'mdi-weather-night'" :label="dark ? 'Switch to the light theme' : 'Switch to the dark theme'" data-test="theme-toggle" @click="theme.toggle()" />
      <span v-if="session.user" class="text-base-content/80 ms-1 hidden text-sm md:inline" data-test="user-email">{{ session.user.email }}</span>
      <UiButton v-if="session.signedIn" variant="text" size="sm" icon-only icon="mdi-logout" :label="t('nav.signout')" data-test="signout" @click="signOut" />
    </template>
    <template #nav="{ close }"><UiNavDrawer :groups="groups" @navigate="close" /></template>
    <slot />
    <UiToast />
    <UiConfirm />
  </UiAppShell>
</template>
