import { z } from 'zod'
import { signInEmail, tenantSlug } from './common'

export const signInSchema = z.object({
  tenant: tenantSlug,
  email: signInEmail,
  password: z.string().min(1, 'Enter your password.').max(1024),
})
export type SignInInput = z.output<typeof signInSchema>
