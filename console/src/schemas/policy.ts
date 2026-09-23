import { z } from 'zod'

/** Go-style durations ("15m", "8h", "1h30m"). */
const duration = z.string().trim().regex(/^(\d+h)?(\d+m)?(\d+s)?$/, 'Use a duration like 15m, 8h or 1h30m.').refine((s) => s.length > 0, 'Enter a duration.')
const seconds = (d: string): number => {
  const m = /^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/.exec(d)
  return m ? Number(m[1] ?? 0) * 3600 + Number(m[2] ?? 0) * 60 + Number(m[3] ?? 0) : 0
}

export const policySchema = z
  .object({
    session_lifetime: duration.refine((d) => seconds(d) <= 86400, 'At most 24h.'),
    idle_timeout: duration,
    access_token_lifetime: duration.refine((d) => seconds(d) <= 900, 'At most 15m.'),
    password_min_length: z.coerce.number().int().min(8, 'At least 8.').max(128),
    mfa_required: z.boolean().optional().transform((v) => v ?? false),
    lockout_threshold: z.coerce.number().int().min(3, 'Between 3 and 20.').max(20, 'Between 3 and 20.'),
    lockout_duration: duration.refine((d) => seconds(d) >= 60 && seconds(d) <= 3600, 'Between 1m and 1h.'),
  })
  .refine((p) => seconds(p.idle_timeout) <= seconds(p.session_lifetime), { path: ['idle_timeout'], message: 'At most the session lifetime.' })
export type PolicyInput = z.output<typeof policySchema>
