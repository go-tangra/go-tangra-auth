import { z } from 'zod'
import { email } from '@go-tangra/ui/forms'

/** Tenant slug: lowercase letters, digits and dashes, 1–63 characters. */
export const tenantSlug = z.string().trim().toLowerCase().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/, 'Use lowercase letters, digits and dashes.')
// Sign-in / forgot-password: blank means "use my e-mail domain" (the server
// derives the tenant, e.g. jane@acme.com → acme).
export const optionalTenantSlug = z.string().trim().toLowerCase().regex(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)?$/, 'Use lowercase letters, digits and dashes.')

export const signInEmail = email

/** A new password: the organisation policy sets the minimum; 8 is the platform floor. */
export const newPassword = (min = 8) => z.string().min(min, `At least ${min} characters.`).max(1024)

/** Two password fields that must match. */
export function withConfirm<T extends z.ZodRawShape>(shape: T, field: keyof T & string, confirm: keyof T & string) {
  return z.object(shape).refine((o) => (o as Record<string, unknown>)[field] === (o as Record<string, unknown>)[confirm], { path: [confirm], message: 'The passwords do not match.' })
}
