<script setup lang="ts">
import { computed, ref, watch } from 'vue'
import { UiDrawer, UiForm, UiInput, UiSelect, UiTextarea, UiCheckbox, UiButton, UiAlert } from '@freya/ui'
import { useZodForm } from '@freya/ui/forms'
import { api } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import { directoryConnectionSchema, directoryCreateSchema, type DirectoryConnection, type DirectoryTestResult, type DirectoryInput } from '@/schemas/directory'

// Mounted anew for each edit; no credential or validation state survives closing.
const props = defineProps<{ connection: DirectoryConnection | null }>()
const emit = defineEmits<{ close: []; saved: [DirectoryConnection] }>()
const testing = ref(false)
const result = ref<DirectoryTestResult | null>(null)
const c = props.connection
const form = useZodForm(c ? directoryConnectionSchema : directoryCreateSchema, {
  initial: {
    name: c?.name ?? '', kind: c?.kind ?? 'other', url: c?.url ?? '', tls_mode: c?.tls_mode ?? 'ldaps',
    allow_tls12: c?.allow_tls12 ?? false, ca_pem: c?.ca_pem, bind_dn: c?.bind_dn ?? '', bind_password: '',
    base_dn: c?.base_dn ?? '', base_filter: c?.base_filter, attributes: { ...c?.attributes },
    size_limit: c?.size_limit, time_limit_seconds: c?.time_limit_seconds,
  },
  onSubmit: (v) => {
    if (testing.value || saving) throw new Error('Request in progress')
    saving = true
    return api<DirectoryConnection>(c ? 'PUT' : 'POST', '/api/v1/admin/directories' + (c ? `/${c.id}` : ''), v).finally(() => { saving = false })
  },
  onSuccess: (saved) => { form.values.bind_password = ''; emit('saved', saved) },
})
let saving = false
const busy = computed(() => testing.value || form.submitting.value)
const kinds = [{ title: 'Active Directory', value: 'active_directory' }, { title: 'OpenLDAP', value: 'openldap' }, { title: 'Other', value: 'other' }]
const tlsModes = [{ title: 'LDAPS', value: 'ldaps' }, { title: 'StartTLS', value: 'starttls' }, { title: 'Plaintext (development only)', value: 'plain' }]
const mappingFields = [
  { key: 'uid', label: 'Unique identifier', test: 'uid' },
  { key: 'email', label: 'Email', test: 'email' },
  { key: 'display_name', label: 'Display name', test: 'display-name' },
  { key: 'first_name', label: 'First name', test: 'first-name' },
  { key: 'last_name', label: 'Last name', test: 'last-name' },
] as const
const attributes = computed(() => form.values.attributes as NonNullable<DirectoryInput['attributes']>)
function preset(kind: unknown): void {
  if (kind !== 'active_directory' && kind !== 'openldap') return
  const defaults = { uid: kind === 'active_directory' ? 'objectGUID' : 'entryUUID', email: 'mail', display_name: kind === 'active_directory' ? 'displayName' : 'cn', first_name: 'givenName', last_name: 'sn' }
  for (const { key } of mappingFields) if (!attributes.value[key]) attributes.value[key] = defaults[key]
}
watch(form.values, () => { result.value = null }, { deep: true })
const steps = { connect: 'Connect', tls: 'TLS', bind: 'Bind', search_base: 'Search base' }
async function test(): Promise<void> {
  if (busy.value) return
  form.setServerError(undefined)
  result.value = null
  const input = form.validate()
  if (!input) return
  testing.value = true
  try {
    result.value = await api<DirectoryTestResult>('POST', '/api/v1/admin/directories/test', { ...input, ...(c?.id ? { connection_id: c.id } : {}) })
  } catch (err) { form.setServerError(err) }
  finally { testing.value = false }
}
</script>

<template>
  <UiDrawer :model-value="true" :title="connection ? 'Edit directory' : 'New directory'" size="lg" :persistent="busy" data-test="directory-drawer" @update:model-value="emit('close')">
    <UiForm :form="form">
      <fieldset :disabled="busy" class="flex flex-col gap-3">
        <UiInput v-bind="form.field('name')" label="Name" required data-test="directory-name" />
        <UiSelect v-bind="form.field('kind')" label="Directory kind" :options="kinds" required :clearable="false" data-test="directory-kind" @change="preset" />
        <UiInput v-bind="form.field('url')" label="Server URL" placeholder="ldaps://directory.example.com:636" required data-test="directory-url" />
        <UiSelect v-bind="form.field('tls_mode')" label="TLS mode" :options="tlsModes" required :clearable="false" data-test="directory-tls-mode" />
        <UiCheckbox v-bind="form.field('allow_tls12')" label="Allow TLS 1.2 for this connection" hint="TLS 1.3 is required by default. Certificate verification always stays enabled." />
        <UiTextarea v-bind="form.field('ca_pem')" label="Trusted CA certificates (PEM)" hint="Leave empty to use system roots. Clearing this field removes a saved CA bundle." />
        <UiInput v-bind="form.field('bind_dn')" label="Bind DN" required data-test="bind-dn" />
        <UiInput v-bind="form.field('bind_password')" label="Bind password" type="password" autocomplete="new-password" :hint="connection?.bind_password_set ? 'stored — leave blank to keep' : undefined" :required="!connection" data-test="bind-password" />
        <UiInput v-bind="form.field('base_dn')" label="Search base DN" required data-test="base-dn" />
        <UiTextarea v-bind="form.field('base_filter')" label="Base filter" hint="Every search is restricted by this filter." />
        <fieldset class="grid grid-cols-1 gap-3 md:grid-cols-2">
          <legend class="mb-2 font-medium">Attribute mapping</legend>
          <UiInput v-for="field in mappingFields" :id="'attributes.' + field.key" :key="field.key" v-model="attributes[field.key]" :label="field.label" :error="form.errors.value['attributes.' + field.key]" :data-test="'attr-' + field.test" @blur="form.blur('attributes.' + field.key)" />
        </fieldset>
        <UiInput v-bind="form.field('size_limit')" type="number" label="Size limit" hint="1–1000 entries; default 500." />
        <UiInput v-bind="form.field('time_limit_seconds')" type="number" label="Time limit (seconds)" hint="1–60 seconds; default 15." />
      </fieldset>
      <UiAlert v-if="result" :kind="result.ok ? 'success' : 'error'" data-test="test-result" role="status">
        <template v-if="result.ok">Connection OK<span v-if="result.tls?.version"> — {{ result.tls.version }}</span></template>
        <template v-else><span data-test="test-step">{{ result.step ? steps[result.step] : 'Connection' }}</span>: <span data-test="test-reason">{{ reasonMessage(result.reason ?? 'directory_error') }}</span></template>
      </UiAlert>
    </UiForm>
    <template #actions>
      <UiButton variant="text" :disabled="busy" @click="emit('close')">Cancel</UiButton>
      <UiButton variant="outline" :disabled="busy" :loading="testing" data-test="test-connection" @click="test">Test connection</UiButton>
      <UiButton :disabled="busy" :loading="form.submitting.value" data-test="save-directory" @click="form.submit()">Save directory</UiButton>
    </template>
  </UiDrawer>
</template>
