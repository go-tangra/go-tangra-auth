import { z } from 'zod'

/** A 6-digit TOTP code or a recovery code (XXXXX-XXXXX). */
export const mfaCode = z.string().trim().regex(/^(\d{6}|[A-Za-z0-9]{5}-[A-Za-z0-9]{5})$/, 'Enter the 6-digit code or a recovery code (XXXXX-XXXXX).')
/** Strictly a 6-digit authenticator code (enrolment, disable, regenerate). */
export const totpCode = z.string().trim().regex(/^\d{6}$/, 'Enter the 6-digit code from your authenticator app.')

export const mfaChallengeSchema = z.object({ code: mfaCode })
export const totpSchema = z.object({ code: totpCode })
export const mfaEnrolSchema = z.object({ code: totpCode })
export const recoveryCodesSavedSchema = z.object({ saved: z.boolean().refine((v) => v, 'Confirm that you saved the codes.') })
