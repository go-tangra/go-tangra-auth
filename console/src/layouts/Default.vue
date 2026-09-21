<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRouter } from 'vue-router'
import { useSession } from '@/stores/session'
import { useI18n } from '@/plugins/i18n'
import type { MessageKey } from '@/plugins/i18n'

const session = useSession()
const router = useRouter()
const { t } = useI18n()
const drawer = ref<boolean | null>(null)

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

const items = computed(() =>
  all.filter((i) => (i.operator ? session.operator : true) && (i.roles ? session.hasAnyRole(i.roles) : true)),
)

async function signOut(): Promise<void> {
  await session.signOut()
  await router.push({ name: 'signin' })
}
</script>

<template>
  <v-app-bar color="primary" density="comfortable">
    <v-app-bar-nav-icon aria-label="Toggle navigation" @click="drawer = !drawer" />
    <v-app-bar-title>{{ session.tenant?.display_name ?? t('app.title') }}</v-app-bar-title>
    <v-spacer />
    <span v-if="session.user" class="mr-4 text-body-2" data-test="user-email">{{ session.user.email }}</span>
    <v-btn v-if="session.signedIn" variant="text" prepend-icon="mdi-logout" data-test="signout" @click="signOut">
      {{ t('nav.signout') }}
    </v-btn>
  </v-app-bar>
  <v-navigation-drawer v-model="drawer">
    <!-- Links, not list items: role="list" would demand listitem children (axe aria-required-children). -->
    <v-list nav density="compact" role="presentation">
      <v-list-item v-for="i in items" :key="i.to" :to="i.to" :prepend-icon="i.icon" :title="t(i.key)" :data-test="'nav-' + i.key" />
    </v-list>
  </v-navigation-drawer>
  <v-main>
    <v-container fluid>
      <slot />
    </v-container>
  </v-main>
</template>
