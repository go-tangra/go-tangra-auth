<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'

export interface Tenant {
  id: string
  slug: string
  display_name: string
  status: string
  kind: string
  created_at: string
}

const tenants = ref<Tenant[]>([])
const error = ref<string | null>(null)
const notice = ref<string | null>(null)
const create = ref(false)
const slug = ref('')
const displayName = ref('')
const ownerEmail = ref('')
const busy = ref(false)
const canCreate = computed(() => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(slug.value) && displayName.value.trim().length > 0 && /^[^\s@]+@[^\s@]+$/.test(ownerEmail.value) && !busy.value)

async function load(): Promise<void> {
  error.value = null
  try {
    tenants.value = (await api<{ items: Tenant[] }>('GET', '/api/v1/operator/tenants')).items
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load tenants.'
  }
}

async function submit(): Promise<void> {
  if (!canCreate.value) return
  busy.value = true
  error.value = null
  try {
    await api('POST', '/api/v1/operator/tenants', { slug: slug.value, display_name: displayName.value.trim(), owner_email: ownerEmail.value })
    notice.value = `Tenant ${slug.value} created; the owner invitation is on its way.`
    create.value = false
    slug.value = ''
    displayName.value = ''
    ownerEmail.value = ''
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not create the tenant.'
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <v-card>
    <v-card-title class="d-flex align-center">
      Tenants
      <v-spacer />
      <v-btn color="primary" prepend-icon="mdi-domain-plus" data-test="create-open" @click="create = true">New tenant</v-btn>
    </v-card-title>
    <v-card-text>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-2" data-test="error">{{ error }}</v-alert>
      <v-alert v-if="notice" type="success" variant="tonal" density="compact" class="mb-2" closable data-test="notice" @click:close="notice = null">{{ notice }}</v-alert>
      <v-table data-test="tenants">
        <thead>
          <tr>
            <th>Name</th>
            <th>Slug</th>
            <th>Status</th>
            <th>Kind</th>
            <th>Created</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="t in tenants" :key="t.id" data-test="tenant-row">
            <td><router-link :to="{ name: 'operator-tenant', params: { id: t.id } }">{{ t.display_name }}</router-link></td>
            <td><code>{{ t.slug }}</code></td>
            <td><v-chip size="small" :color="t.status === 'active' ? 'success' : 'error'" data-test="status">{{ t.status }}</v-chip></td>
            <td>{{ t.kind }}</td>
            <td>{{ t.created_at }}</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
    <v-dialog v-model="create" max-width="480">
      <v-card data-test="create-dialog">
        <v-card-title>New tenant</v-card-title>
        <v-card-text>
          <v-text-field v-model.trim="slug" label="Slug" hint="lowercase letters, digits and dashes" persistent-hint data-test="slug" />
          <v-text-field v-model="displayName" label="Display name" data-test="name" />
          <v-text-field v-model.trim="ownerEmail" label="Owner email" type="email" data-test="owner" />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="create = false">Cancel</v-btn>
          <v-btn color="primary" :disabled="!canCreate" :loading="busy" data-test="create" @click="submit">Create</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-card>
</template>
