import { ref } from 'vue'
import QRCode from 'qrcode'
import { api, ApiError } from '@/api/client'
import { reasonMessage } from '@/api/vocab'

export interface Enrolment {
  secret: string
  otpauth_uri: string
}

/** Drives the TOTP enrolment wizard: enrol → QR → confirm → recovery codes (shown once). */
export function useMfa() {
  const enrolment = ref<Enrolment | null>(null)
  const qr = ref<string>('')
  const recoveryCodes = ref<string[]>([])
  const error = ref<string | null>(null)
  const busy = ref(false)

  async function start(): Promise<void> {
    error.value = null
    busy.value = true
    try {
      enrolment.value = await api<Enrolment>('POST', '/api/v1/me/mfa/enroll')
      qr.value = await QRCode.toDataURL(enrolment.value.otpauth_uri, { errorCorrectionLevel: 'M', margin: 1, width: 192 })
    } catch (err) {
      error.value = err instanceof ApiError ? reasonMessage(err.reason) : 'Could not start enrolment.'
    } finally {
      busy.value = false
    }
  }

  async function confirm(code: string): Promise<boolean> {
    error.value = null
    busy.value = true
    try {
      const res = await api<{ recovery_codes: string[] }>('POST', '/api/v1/me/mfa/confirm', { code })
      recoveryCodes.value = res.recovery_codes
      enrolment.value = null
      qr.value = ''
      return true
    } catch (err) {
      error.value = err instanceof ApiError && err.reason === 'invalid_code' ? 'That code was not accepted. Codes change every 30 seconds.' : 'Could not confirm enrolment.'
      return false
    } finally {
      busy.value = false
    }
  }

  return { enrolment, qr, recoveryCodes, error, busy, start, confirm }
}
