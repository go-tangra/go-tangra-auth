<script setup lang="ts">
import { onMounted, ref, watch } from 'vue'
import { ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { useGroups, type Group } from '@/stores/groups'

const groups = useGroups()
const q = ref('')
const error = ref<string | null>(null)
const busy = ref(false)
const dialog = ref(false)
const editing = ref<Group | null>(null)
const name = ref('')
const description = ref('')
const confirmDelete = ref<Group | null>(null)

function openNew(): void {
  editing.value = null
  name.value = ''
  description.value = ''
  error.value = null
  dialog.value = true
}

function openEdit(g: Group): void {
  editing.value = g
  name.value = g.name ?? ''
  description.value = g.description ?? ''
  error.value = null
  dialog.value = true
}

const nameRules = [(v: string) => (v.trim().length > 0 && v.trim().length <= 64) || 'Between 1 and 64 characters']

async function save(): Promise<void> {
  if (nameRules[0]!(name.value) !== true) return
  busy.value = true
  error.value = null
  try {
    if (editing.value?.id) await groups.update(editing.value.id, name.value.trim(), description.value.trim())
    else await groups.create(name.value.trim(), description.value.trim())
    dialog.value = false
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not save the group.'
  } finally {
    busy.value = false
  }
}

async function remove(): Promise<void> {
  const g = confirmDelete.value
  if (!g?.id) return
  busy.value = true
  error.value = null
  try {
    await groups.remove(g.id, g.member_count ?? 0)
    confirmDelete.value = null
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not delete the group.'
    if (err instanceof ApiError && err.reason === 'member_count_mismatch') await groups.load(q.value)
  } finally {
    busy.value = false
  }
}

let timer: number | undefined
watch(q, () => {
  window.clearTimeout(timer)
  timer = window.setTimeout(() => void groups.load(q.value), 250)
})
onMounted(() => groups.load())
</script>

<template>
  <v-card data-test="groups">
    <v-card-title class="d-flex align-center">
      Groups
      <v-spacer />
      <v-btn color="primary" prepend-icon="mdi-plus" data-test="new-group" @click="openNew">New group</v-btn>
    </v-card-title>
    <v-card-text>
      <v-text-field v-model="q" label="Search" prepend-inner-icon="mdi-magnify" density="compact" clearable data-test="search" />
      <v-alert v-if="error && !dialog && !confirmDelete" type="error" variant="tonal" density="compact" class="mb-2" data-test="error">{{ error }}</v-alert>
      <v-table>
        <thead>
          <tr>
            <th>Group</th>
            <th>Members</th>
            <th>Roles</th>
            <th />
          </tr>
        </thead>
        <tbody>
          <tr v-for="g in groups.items" :key="g.id ?? ''" data-test="group-row">
            <td>
              <router-link :to="{ name: 'admin-group', params: { id: g.id ?? '' } }" data-test="group-name">{{ g.name }}</router-link>
              <div v-if="g.description" class="text-caption">{{ g.description }}</div>
            </td>
            <td data-test="member-count">{{ g.member_count }}</td>
            <td>{{ (g.roles ?? []).join(', ') || '—' }}</td>
            <td class="text-right text-no-wrap">
              <v-btn size="small" variant="text" data-test="edit" @click="openEdit(g)">Rename</v-btn>
              <v-btn size="small" variant="text" color="error" data-test="delete-group" @click="confirmDelete = g">Delete</v-btn>
            </td>
          </tr>
          <tr v-if="groups.loaded && groups.items.length === 0">
            <td colspan="4" class="text-caption">No groups yet.</td>
          </tr>
        </tbody>
      </v-table>
    </v-card-text>
  </v-card>

  <v-dialog v-model="dialog" max-width="480">
    <v-card data-test="group-dialog">
      <v-card-title>{{ editing ? 'Rename group' : 'New group' }}</v-card-title>
      <v-card-text>
        <v-text-field v-model="name" label="Name" :rules="nameRules" counter="64" maxlength="64" autofocus data-test="group-name-input" />
        <v-text-field v-model="description" label="Description" counter="500" maxlength="500" data-test="group-description" />
        <v-alert v-if="error" type="error" variant="tonal" density="compact" data-test="dialog-error">{{ error }}</v-alert>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="dialog = false">Cancel</v-btn>
        <v-btn color="primary" :loading="busy" :disabled="busy" data-test="save-group" @click="save">Save</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>

  <v-dialog :model-value="confirmDelete !== null" max-width="480" @update:model-value="confirmDelete = null">
    <v-card v-if="confirmDelete" data-test="delete-dialog">
      <v-card-title>Delete {{ confirmDelete.name }}?</v-card-title>
      <v-card-text>
        <p data-test="delete-summary">
          {{ confirmDelete.member_count }} member{{ confirmDelete.member_count === 1 ? '' : 's' }} will lose the roles this group grants:
          {{ (confirmDelete.roles ?? []).join(', ') || 'none' }}.
        </p>
        <v-alert v-if="error" type="error" variant="tonal" density="compact" data-test="dialog-error">{{ error }}</v-alert>
      </v-card-text>
      <v-card-actions>
        <v-spacer />
        <v-btn variant="text" @click="confirmDelete = null">Cancel</v-btn>
        <v-btn color="error" :loading="busy" :disabled="busy" data-test="confirm-delete" @click="remove">Delete group</v-btn>
      </v-card-actions>
    </v-card>
  </v-dialog>
</template>
