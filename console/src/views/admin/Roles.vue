<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useRoles } from '@/composables/useRoles'

const { roles, load } = useRoles()
const error = ref<string | null>(null)
const busy = ref(false)

async function remove(id: string | undefined): Promise<void> {
  if (!id) return
  busy.value = true
  error.value = null
  try {
    await api('POST', `/api/v1/admin/roles/${encodeURIComponent(id)}/remove`)
    await load()
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not remove the role.'
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <v-card>
    <v-card-title class="d-flex align-center">
      Roles
      <v-spacer />
      <v-btn color="primary" prepend-icon="mdi-plus" :to="{ name: 'admin-role-new' }" data-test="new-role">New role</v-btn>
    </v-card-title>
    <v-card-text>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" class="mb-2" data-test="error">{{ error }}</v-alert>
      <v-table data-test="roles">
        <thead>
          <tr>
            <th>Role</th>
            <th>Slug</th>
            <th>Permissions</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr v-for="r in roles" :key="r.id" data-test="role-row">
            <td>
              {{ r.display_name }}
              <v-chip v-if="r.builtin" size="x-small" class="ml-2" data-test="builtin">built-in</v-chip>
            </td>
            <td><code>{{ r.slug }}</code></td>
            <td>{{ r.builtin ? 'defined by the platform' : (r.permissions ?? []).join(', ') || '—' }}</td>
            <td class="text-right text-no-wrap">
              <v-btn v-if="!r.builtin" size="small" variant="text" :to="{ name: 'admin-role', params: { id: r.id } }" data-test="edit">Edit</v-btn>
              <v-btn v-if="!r.builtin" size="small" variant="text" color="error" :disabled="busy" data-test="remove" @click="remove(r.id)">Remove</v-btn>
            </td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>
</template>
