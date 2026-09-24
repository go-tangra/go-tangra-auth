import { z } from 'zod'
import { optionalString } from '@go-tangra/ui/forms'
import { signInEmail } from './common'

export const inviteSchema = z.object({
  email: signInEmail,
  first_name: optionalString(100),
  last_name: optionalString(100),
  role_ids: z.array(z.string()).optional().transform((v) => v ?? []),
  group_ids: z.array(z.string()).optional().transform((v) => v ?? []),
})
export type InviteInput = z.output<typeof inviteSchema>
