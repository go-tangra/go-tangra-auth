import { z } from 'zod'
import { optionalString } from '@go-tangra/ui/forms'

export const groupSchema = z.object({
  name: z.string().trim().min(1, 'Between 1 and 64 characters.').max(64, 'Between 1 and 64 characters.'),
  description: optionalString(500).transform((v) => v ?? ''),
})
export type GroupInput = z.output<typeof groupSchema>
export const addMemberSchema = z.object({ user_id: z.string().min(1, 'Pick a person.') })
