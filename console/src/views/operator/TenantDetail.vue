<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import type { Tenant } from './Tenants.vue'

const route = useRoute()
const id = computed(() => String(route.params.id ?? ''))
const tenant = ref<Tenant | null>(null)
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const confirmSuspend = ref(false)
const grantDialog = ref(false)
const reason = ref('')
const duration = ref('1h')
const busy = ref(false)
const grant = ref<{ id: string; expires_at: string } | null>(null)
const canGrant = computed(() => reason.value.trim().length >= 10 && /^([1-4]h|[1-9]\d?m|[1-3]h[0-5]?\dm)$/.test(duration.value) && !busy.value)

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
    confirmSuspend.value = false
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'The action failed.'
  } finally {
    busy.value = false
  }
}

async function createGrant(): Promise<void> {
  if (!canGrant.value) return
  busy.value = true
  error.value = null
  try {
    grant.value = await api<{ id: string; expires_at: string }>('POST', '/api/v1/operator/grants', { tenant_id: id.value, reason: reason.value.trim(), duration: duration.value })
    grantDialog.value = false
    reason.value = ''
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not create the grant.'
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <v-card v-if="tenant" data-test="tenant-detail">
    <v-card-title>{{ tenant.display_name }} <v-chip size="small" class="ml-2" :color="tenant.status === 'active' ? 'success' : 'error'" data-test="status">{{ tenant.status }}</v-chip></v-card-title>
    <v-card-subtitle><code>{{ tenant.slug }}</code> · {{ tenant.kind }}</v-card-subtitle>
    <v-card-text>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-2" data-test="error">{{ error }}</v-alert>
      <v-alert v-if="notice" type="success" variant="tonal" density="compact" class="mb-2" data-test="notice">{{ notice }}</v-alert>
      <v-alert v-if="grant" type="info" variant="tonal" density="compact" class="mb-2" data-test="grant">
        Access grant active until {{ grant.expires_at }}. Every action you take in this tenant is audited under your name.
      </v-alert>
    </v-card-text>
    <v-card-actions>
      <v-btn v-if="tenant.status === 'active' && tenant.kind !== 'platform'" color="error" variant="outlined" data-test="suspend-open" @click="confirmSuspend = true">Suspend</v-btn>
      <v-btn v-if="tenant.status === 'suspended'" color="primary" variant="outlined" :disabled="busy" data-test="reactivate" @click="setStatus('reactivate')">Reactivate</v-btn>
      <v-btn v-if="tenant.kind !== 'platform'" variant="text" data-test="grant-open" @click="grantDialog = true">Request access grant</v-btn>
      <v-spacer />
      <v-btn variant="text" :to="{ name: 'operator-tenants' }">Back</v-btn>
    </v-card-actions>
    <v-dialog v-model="confirmSuspend" max-width="420">
      <v-card data-test="suspend-dialog">
        <v-card-title>Suspend {{ tenant.display_name }}?</v-card-title>
        <v-card-text>All users of this tenant are signed out immediately and cannot sign in until it is reactivated. Tokens stop verifying within seconds.</v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="confirmSuspend = false">Cancel</v-btn>
          <v-btn color="error" :loading="busy" data-test="suspend-confirm" @click="setStatus('suspend')">Suspend</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
    <v-dialog v-model="grantDialog" max-width="480">
      <v-card data-test="grant-dialog">
        <v-card-title>Access grant</v-card-title>
        <v-card-text>
          <v-textarea v-model="reason" label="Reason (ticket, incident…)" rows="2" hint="At least 10 characters; recorded in the audit trail" persistent-hint data-test="reason" />
          <v-select v-model="duration" :items="['15m', '30m', '1h', '2h', '4h']" label="Duration" data-test="duration" />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="grantDialog = false">Cancel</v-btn>
          <v-btn color="primary" :disabled="!canGrant" :loading="busy" data-test="grant-create" @click="createGrant">Create grant</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-card>
  <v-alert v-else-if="error" type="warning" variant="tonal" data-test="error">{{ error }}</v-alert>
</template>
