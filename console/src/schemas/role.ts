import { z } from 'zod'
import { nonEmpty } from '@freya/ui/forms'

export const BUILTIN_ROLES = ['owner', 'admin', 'member'] as const
export const roleSchema = z.object({
  slug: z.string().trim().regex(/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/, 'Lowercase letters, digits and dashes.').refine((s) => !(BUILTIN_ROLES as readonly string[]).includes(s), 'That slug is reserved for a built-in role.'),
  display_name: nonEmpty(100),
  permissions: z.array(z.string().regex(/^[a-z0-9_-]+:[a-z0-9_-]+$/)).optional().transform((v) => v ?? []),
})
export type RoleInput = z.output<typeof roleSchema>
export const roleAssignmentSchema = z.object({ role_ids: z.array(z.string()) })
