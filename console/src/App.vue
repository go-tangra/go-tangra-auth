<script setup lang="ts">
// Root shell: routes declare their layout ("default" for signed-in views,
// "bare" for sign-in, recovery, invitation and outage pages).
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import DefaultLayout from './layouts/Default.vue'
import BareLayout from './layouts/Bare.vue'

const route = useRoute()
const layout = computed(() => (route.meta.layout === 'bare' ? BareLayout : DefaultLayout))
</script>

<template>
  <v-app>
    <component :is="layout">
      <router-view />
    </component>
  </v-app>
</template>
