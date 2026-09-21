<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'

interface Client {
  client_id: string
  display_name: string
  redirect_uris: string[]
  public: boolean
}

const clients = ref<Client[]>([])
const error = ref<string | null>(null)
const dialog = ref(false)
const name = ref('')
const uris = ref('')
const isPublic = ref(true)
const busy = ref(false)
const created = ref<(Client & { client_secret?: string }) | null>(null)
const uriList = computed(() => uris.value.split('\n').map((u) => u.trim()).filter(Boolean))
const canCreate = computed(() => name.value.trim().length > 0 && uriList.value.length > 0 && uriList.value.every((u) => /^https:\/\/|^http:\/\/(localhost|127\.0\.0\.1)/.test(u)) && !busy.value)

async function load(): Promise<void> {
  try {
    clients.value = await api<Client[]>('GET', '/api/v1/admin/clients')
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load applications.'
  }
}

async function create(): Promise<void> {
  if (!canCreate.value) return
  busy.value = true
  error.value = null
  try {
    created.value = await api<Client & { client_secret?: string }>('POST', '/api/v1/admin/clients', { display_name: name.value.trim(), redirect_uris: uriList.value, public: isPublic.value })
    dialog.value = false
    name.value = ''
    uris.value = ''
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not register the application.'
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <v-card>
    <v-card-title class="d-flex align-center">
      Applications
      <v-spacer />
      <v-btn color="primary" prepend-icon="mdi-plus" data-test="client-open" @click="dialog = true">Register</v-btn>
    </v-card-title>
    <v-card-text>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-2" data-test="error">{{ error }}</v-alert>
      <v-alert v-if="created" type="success" variant="tonal" class="mb-4" data-test="created">
        <div>Client id: <code data-test="client-id">{{ created.client_id }}</code></div>
        <div v-if="created.client_secret">Client secret (shown once): <code data-test="client-secret">{{ created.client_secret }}</code></div>
        <v-btn size="small" variant="text" class="mt-2" data-test="created-dismiss" @click="created = null">Dismiss</v-btn>
      </v-alert>
      <v-table data-test="clients">
        <thead>
          <tr>
            <th>Name</th>
            <th>Client id</th>
            <th>Type</th>
            <th>Redirect URIs</th>
          </tr>
        </thead>
        <tbody>
          <tr v-for="c in clients" :key="c.client_id" data-test="client-row">
            <td>{{ c.display_name }}</td>
            <td><code>{{ c.client_id }}</code></td>
            <td>{{ c.public ? 'public (PKCE)' : 'confidential' }}</td>
            <td>{{ c.redirect_uris.join(', ') }}</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
    <v-dialog v-model="dialog" max-width="520">
      <v-card data-test="client-dialog">
        <v-card-title>Register an application</v-card-title>
        <v-card-text>
          <v-text-field v-model="name" label="Name" data-test="client-name" />
          <v-textarea v-model="uris" label="Redirect URIs (one per line, https)" rows="3" data-test="client-uris" />
          <v-switch v-model="isPublic" label="Public client (browser / mobile, PKCE only)" color="primary" data-test="client-public" />
        </v-card-text>
        <v-card-actions>
          <v-spacer />
          <v-btn variant="text" @click="dialog = false">Cancel</v-btn>
          <v-btn color="primary" :disabled="!canCreate" :loading="busy" data-test="client-create" @click="create">Register</v-btn>
        </v-card-actions>
      </v-card>
    </v-dialog>
  </v-card>
</template>
