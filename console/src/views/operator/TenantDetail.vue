<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { UiPage, UiCard, UiAlert, UiButton, UiStatusChip, UiRecordDrawer, useConfirm } from '@go-tangra/ui'
import { zodToFields } from '@go-tangra/ui/forms'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { GRANT_DURATIONS, grantSchema } from '@/schemas'
import type { Tenant } from './Tenants.vue'

const route = useRoute()
const router = useRouter()
const { ask } = useConfirm()
const id = computed(() => String(route.params.id ?? ''))
const tenant = ref<Tenant | null>(null)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const grantDialog = ref(false)
const busy = ref(false)
const grant = ref<{ id: string; expires_at: string } | null>(null)
const grantFields = zodToFields(grantSchema, {
  reason: { label: 'Reason (ticket, incident…)', type: 'textarea', hint: 'At least 10 characters; recorded in the audit trail', cols: 12 },
  duration: { type: 'select', options: GRANT_DURATIONS.map((d) => ({ title: d, value: d })), cols: 12 },
})

async function load(): Promise<void> {
  const list = (await api<{ items: Tenant[] }>('GET', '/api/v1/operator/tenants')).items
  tenant.value = list.find((t) => t.id === id.value) ?? null
  if (!tenant.value) error.value = reasonMessage('not_found')
}

async function setStatus(op: 'suspend' | 'reactivate'): Promise<void> {
  busy.value = true
  error.value = null
  try {
    await api('POST', `/api/v1/operator/tenants/${encodeURIComponent(id.value)}/${op}`)
    notice.value = op === 'suspend' ? 'Tenant suspended. Every session in it was ended.' : 'Tenant reactivated.'
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'The action failed.'
  } finally {
    busy.value = false
  }
}
async function suspend(): Promise<void> {
  if (!tenant.value) return
  const ok = await ask({ title: `Suspend ${tenant.value.display_name}?`, text: 'All users of this tenant are signed out immediately and cannot sign in until it is reactivated. Tokens stop verifying within seconds.', confirmLabel: 'Suspend', danger: true })
  if (ok) await setStatus('suspend')
}
const createGrant = (v: Record<string, unknown>) => api<{ id: string; expires_at: string }>('POST', '/api/v1/operator/grants', { tenant_id: id.value, ...v })
onMounted(load)
</script>

<template>
  <UiPage v-if="tenant" :title="tenant.display_name" :subtitle="`${tenant.slug} · ${tenant.kind}`" data-test="tenant-detail">
    <template #before-title><UiButton variant="text" icon="mdi-arrow-left" icon-only label="Back to tenants" @click="router.push({ name: 'operator-tenants' })" /></template>
    <template #badges><UiStatusChip :status="tenant.status" :colors="{ active: 'success', suspended: 'error' }" data-test="status" /></template>
    <template #actions>
      <UiButton v-if="tenant.status === 'active' && tenant.kind !== 'platform'" color="error" variant="outline" data-test="suspend-open" @click="suspend">Suspend</UiButton>
      <UiButton v-if="tenant.status === 'suspended'" variant="outline" :disabled="busy" data-test="reactivate" @click="setStatus('reactivate')">Reactivate</UiButton>
      <UiButton v-if="tenant.kind !== 'platform'" variant="text" data-test="grant-open" @click="grantDialog = true">Request access grant</UiButton>
    </template>
    <UiCard>
      <UiAlert v-if="error" kind="error" class="mb-2" data-test="error">{{ error }}</UiAlert>
      <UiAlert v-if="notice" kind="success" class="mb-2" data-test="notice">{{ notice }}</UiAlert>
      <UiAlert v-if="grant" kind="info" class="mb-2" data-test="grant">Access grant active until {{ new Date(grant.expires_at).toLocaleString() }}. Every action you take in this tenant is audited under your name.</UiAlert>
      <p v-if="!error && !notice && !grant" class="text-base-content/70 text-sm">Suspending signs every user of this tenant out at once; an access grant lets you act inside it for a bounded, audited window.</p>
    </UiCard>
    <UiRecordDrawer v-model="grantDialog" close-on-save title="Access grant" :schema="grantSchema" :fields="grantFields" :initial="{ reason: '', duration: '1h' }" :submit="createGrant" save-label="Create grant" size="md" data-test="grant-dialog" @saved="grant = $event as { id: string; expires_at: string }" />
  </UiPage>
  <UiAlert v-else-if="error" kind="warning" data-test="error">{{ error }}</UiAlert>
</template>
