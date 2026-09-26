import { z } from 'zod'
import { nonEmpty } from '@go-tangra/ui/forms'

/** Slugs of the platform's built-in roles; custom roles may not take them. */
export const BUILTIN_ROLES = ['owner', 'admin', 'member', 'auditor', 'operator'] as const

/** Qualified permission reference `module:resource:action` (contracts/http.md). */
export const QUALIFIED_PERMISSION = /^[a-z][a-z0-9-]{0,31}:[a-z][a-z0-9_-]{0,63}:[a-z][a-z0-9_-]{0,31}$/
/** Pre-module `resource:action` reference; only ever kept on a role that already holds it. */
export const LEGACY_PERMISSION = /^[a-z][a-z0-9_-]{0,63}:[a-z][a-z0-9_-]{0,31}$/
export const isLegacyPermission = (ref: string): boolean => LEGACY_PERMISSION.test(ref)

/** Custom-role slug: lowercase letters, digits and dashes; no dots (module roles), no built-in names. */
export const customRoleSlug = z
  .string()
  .trim()
  .refine((s) => !s.includes('.'), 'Dots are reserved for module roles.')
  .regex(/^[a-z0-9](?:[a-z0-9-]{0,62}[a-z0-9])?$/, 'Lowercase letters, digits and dashes.')
  .refine((s) => !(BUILTIN_ROLES as readonly string[]).includes(s), 'That slug is reserved for a built-in role.')

export const roleSchema = z.object({
  slug: customRoleSlug,
  display_name: nonEmpty(100),
  permissions: z
    .array(z.string().refine((p) => QUALIFIED_PERMISSION.test(p) || LEGACY_PERMISSION.test(p), 'Unknown permission reference.'))
    .optional()
    .transform((v) => v ?? []),
})
export type RoleInput = z.output<typeof roleSchema>
export const roleAssignmentSchema = z.object({ role_ids: z.array(z.string()) })

/** POST /admin/roles/{id}/clone body. */
export const roleCloneSchema = z.object({ slug: customRoleSlug, display_name: nonEmpty(100) })
export type RoleCloneInput = z.output<typeof roleCloneSchema>

/** Suggests a custom-role slug from a name: lowercase, runs of other characters → '-', trimmed, at most 63. */
export function suggestSlug(name: string): string {
  const trim = (s: string) => s.replace(/^-+|-+$/g, '')
  return trim(trim(name.toLowerCase().replace(/[^a-z0-9]+/g, '-')).slice(0, 63))
}
