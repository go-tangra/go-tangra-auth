<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'
import type { components } from '@/api/schema'

type Policy = Required<components['schemas']['Policy']>

const policy = ref<Policy>({ session_lifetime: '8h', idle_timeout: '1h', access_token_lifetime: '15m', password_min_length: 12, mfa_required: false, lockout_threshold: 10, lockout_duration: '15m' })
const error = ref<string | null>(null)
const saved = ref(false)
const busy = ref(false)

async function load(): Promise<void> {
  try {
    policy.value = { ...policy.value, ...(await api<Policy>('GET', '/api/v1/admin/policy')) }
  } catch (err) {
    error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not load the policy.'
  }
}

async function save(): Promise<void> {
  busy.value = true
  error.value = null
  saved.value = false
  try {
    policy.value = { ...policy.value, ...(await api<Policy>('PUT', '/api/v1/admin/policy', { ...policy.value, password_min_length: Number(policy.value.password_min_length), lockout_threshold: Number(policy.value.lockout_threshold) })) }
    saved.value = true
  } catch (err) {
    error.value = err instanceof ApiError ? (err.reason === 'validation_failed' ? 'One of the values is out of range (lifetimes ≤ 24h, token ≤ 15m, min length ≥ 8, lockout 3–20 / 1m–1h).' : reasonMessage(err.reason)) : 'Could not save the policy.'
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <v-card data-test="policy">
    <v-card-title>Security policy</v-card-title>
    <v-card-text>
      <v-row dense>
        <v-col cols="12" md="4"><v-text-field v-model="policy.session_lifetime" label="Session lifetime" hint="≤ 24h" data-test="session_lifetime" /></v-col>
        <v-col cols="12" md="4"><v-text-field v-model="policy.idle_timeout" label="Idle timeout" hint="≤ session lifetime" data-test="idle_timeout" /></v-col>
        <v-col cols="12" md="4"><v-text-field v-model="policy.access_token_lifetime" label="Access token lifetime" hint="≤ 15m" data-test="access_token_lifetime" /></v-col>
        <v-col cols="12" md="4"><v-text-field v-model.number="policy.password_min_length" label="Minimum password length" type="number" min="8" data-test="password_min_length" /></v-col>
        <v-col cols="12" md="4"><v-text-field v-model.number="policy.lockout_threshold" label="Lockout threshold" type="number" min="3" max="20" data-test="lockout_threshold" /></v-col>
        <v-col cols="12" md="4"><v-text-field v-model="policy.lockout_duration" label="Lockout duration" hint="1m – 1h" data-test="lockout_duration" /></v-col>
        <v-col cols="12"><v-switch v-model="policy.mfa_required" label="Require a second factor for every user" color="primary" data-test="mfa_required" /></v-col>
      </v-row>
      <v-alert v-if="error" type="error" variant="tonal" density="compact" data-test="error">{{ error }}</v-alert>
      <v-alert v-if="saved" type="success" variant="tonal" density="compact" data-test="saved">Policy saved. It applies to new sign-ins and decisions immediately.</v-alert>
    </v-card-text>
    <v-card-actions>
      <v-btn color="primary" :loading="busy" data-test="save" @click="save">Save policy</v-btn>
    </v-card-actions>
  </v-card>
</template>
