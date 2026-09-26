<script setup lang="ts">
// Security keys of the signed-in user (feature 018): list, add, rename and
// remove. Removal is confirmed with a current second factor: a code
// (authenticator or recovery) or a key assertion (step-up).
import { computed, ref } from 'vue'
import { UiAlert, UiBadge, UiButton, UiDialog, UiIcon, UiInput } from '@go-tangra/ui'
import { useZodForm } from '@go-tangra/ui/forms'
import { api } from '@/api/client'
import { useWebAuthn, webAuthnMessage, type KeyView } from '@/composables/useWebAuthn'
import { keyNameSchema, mfaChallengeSchema } from '@/schemas'

const props = defineProps<{ keys: KeyView[]; rpId: string; totp: boolean }>()
const emit = defineEmits<{ changed: []; codes: [codes: string[]] }>()
const wa = useWebAuthn()
const { supported, busy } = wa
const canAssert = computed(() => supported && props.keys.some((k) => !k.flagged))
const url = (id: string) => `/api/v1/me/mfa/webauthn/${encodeURIComponent(id)}`
const fmt = (at: string) => new Date(at).toLocaleString()

// --- add ---
const addError = ref<string | null>(null)
const addForm = useZodForm(keyNameSchema, {
  initial: { name: '' },
  onSubmit: async (v) => {
    addError.value = null
    const res = await wa.register(v.name)
    if (!res) {
      addError.value = wa.error.value
      throw new Error(addError.value ?? 'registration_failed')
    }
    addForm.reset({ name: '' })
    if (res.recovery_codes?.length) emit('codes', res.recovery_codes)
    emit('changed')
  },
})

// --- rename ---
const renaming = ref<KeyView | null>(null)
const renameError = ref<string | null>(null)
const renameForm = useZodForm(keyNameSchema, {
  initial: { name: '' },
  onSubmit: async (v) => {
    if (!renaming.value) return
    renameError.value = null
    try {
      await api('PATCH', url(renaming.value.id), { name: v.name })
      renaming.value = null
      emit('changed')
    } catch (err) {
      renameError.value = webAuthnMessage(err)
      throw err
    }
  },
})
function startRename(k: KeyView): void {
  renameError.value = null
  renameForm.reset({ name: k.name })
  renaming.value = k
}

// --- remove ---
const removing = ref<KeyView | null>(null)
const removeError = ref<string | null>(null)
const removeBusy = ref(false)
async function remove(confirmation: { code: string } | { credential: unknown }): Promise<void> {
  if (!removing.value) return
  removeBusy.value = true
  try {
    await api('DELETE', url(removing.value.id), confirmation)
    removing.value = null
    emit('changed')
  } catch (err) {
    removeError.value = webAuthnMessage(err)
    throw err
  } finally {
    removeBusy.value = false
  }
}
const codeForm = useZodForm(mfaChallengeSchema, {
  initial: { code: '' },
  onSubmit: async (v) => {
    removeError.value = null
    try {
      await remove({ code: v.code })
    } finally {
      codeForm.reset({ code: '' })
    }
  },
})
async function removeWithKey(): Promise<void> {
  removeError.value = null
  const credential = await wa.stepUp()
  if (!credential) {
    removeError.value = wa.error.value
    return
  }
  await remove({ credential }).catch(() => undefined)
}
function startRemove(k: KeyView): void {
  removeError.value = null
  codeForm.reset({ code: '' })
  removing.value = k
}
</script>

<template>
  <div data-test="security-keys">
    <ul v-if="keys.length" class="mb-4 divide-y divide-base-300" data-test="key-list">
      <li v-for="k in keys" :key="k.id" class="flex flex-wrap items-center gap-2 py-2" data-test="key-row">
        <UiIcon name="mdi-key-variant" />
        <div class="grow">
          <div class="font-medium">
            {{ k.name }}
            <UiBadge v-if="k.flagged" color="error" data-test="key-flagged">Possibly cloned</UiBadge>
          </div>
          <div class="text-xs text-base-content/70">
            Added <time :datetime="k.created_at">{{ fmt(k.created_at) }}</time> ·
            <template v-if="k.last_used_at">last used <time :datetime="k.last_used_at">{{ fmt(k.last_used_at) }}</time></template>
            <template v-else>Never used</template>
          </div>
        </div>
        <UiButton size="sm" variant="text" icon="mdi-pencil-outline" data-test="rename" @click="startRename(k)">Rename</UiButton>
        <UiButton size="sm" variant="text" color="error" icon="mdi-delete-outline" data-test="remove" @click="startRemove(k)">Remove</UiButton>
      </li>
    </ul>
    <p v-else class="mb-4 text-sm text-base-content/70" data-test="no-keys">No security keys registered.</p>

    <div v-if="supported" class="flex flex-wrap items-end gap-2">
      <UiInput v-bind="addForm.field('name')" label="New key name" placeholder="YubiKey 5C – desk" autocomplete="off" class="grow" data-test="key-name" @enter="addForm.submit()" />
      <UiButton variant="outline" icon="mdi-key-plus" :loading="busy" data-test="add-key" @click="addForm.submit()">Add security key</UiButton>
    </div>
    <p v-else class="text-sm text-base-content/70" data-test="key-unsupported">This browser does not support security keys.</p>
    <UiAlert v-if="addError" kind="error" class="mt-2" role="alert" data-test="key-error">{{ addError }}</UiAlert>
    <p v-if="rpId" class="mt-2 text-xs text-base-content/70">Keys work only at {{ rpId }}.</p>

    <UiDialog :model-value="renaming !== null" title="Rename security key" size="sm" data-test="rename-dialog" @update:model-value="renaming = null">
      <UiInput v-bind="renameForm.field('name')" label="Name" autocomplete="off" required data-test="rename-name" @enter="renameForm.submit()" />
      <UiAlert v-if="renameError" kind="error" class="mt-2" role="alert" data-test="rename-error">{{ renameError }}</UiAlert>
      <template #actions>
        <UiButton variant="text" @click="renaming = null">Cancel</UiButton>
        <UiButton :loading="renameForm.submitting.value" data-test="rename-save" @click="renameForm.submit()">Save</UiButton>
      </template>
    </UiDialog>

    <UiDialog :model-value="removing !== null" :title="`Remove ${removing?.name ?? ''}?`" size="sm" data-test="remove-dialog" @update:model-value="removing = null">
      <p class="mb-3 text-sm">The key stops working immediately. Confirm with a current second factor.</p>
      <UiButton v-if="canAssert" block variant="outline" icon="mdi-key" :loading="busy" class="mb-3" data-test="remove-with-key" @click="removeWithKey">Confirm with a security key</UiButton>
      <div class="flex flex-wrap items-end gap-2">
        <UiInput v-bind="codeForm.field('code')" :label="totp ? 'Authenticator or recovery code' : 'Recovery code'" autocomplete="one-time-code" class="grow" data-test="remove-code" @enter="codeForm.submit()" />
        <UiButton color="error" :loading="removeBusy" data-test="remove-with-code" @click="codeForm.submit()">Remove</UiButton>
      </div>
      <UiAlert v-if="removeError" kind="error" class="mt-2" role="alert" data-test="remove-error">{{ removeError }}</UiAlert>
      <template #actions>
        <UiButton variant="text" @click="removing = null">Cancel</UiButton>
      </template>
    </UiDialog>
  </div>
</template>
