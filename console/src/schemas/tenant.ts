import { z } from 'zod'
import { nonEmpty } from '@freya/ui/forms'
import { signInEmail, tenantSlug } from './common'

export const tenantSchema = z.object({
  slug: tenantSlug,
  display_name: nonEmpty(100),
  owner_email: signInEmail,
})
export type TenantInput = z.output<typeof tenantSchema>

export const GRANT_DURATIONS = ['15m', '30m', '1h', '2h', '4h'] as const
export const grantSchema = z.object({
  reason: z.string().trim().min(10, 'At least 10 characters; recorded in the audit trail.').max(500),
  duration: z.enum(GRANT_DURATIONS),
})
