import { z } from 'zod'
import { email } from '@go-tangra/ui/forms'
import { firstBroken, PASSWORD_FLOOR, ruleError, type PasswordRequirements } from '@/password/rules'

/** Tenant slug: lowercase letters, digits and dashes, 1–63 characters. */
export const tenantSlug = z.string().trim().toLowerCase().regex(/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/, 'Use lowercase letters, digits and dashes.')
// Sign-in / forgot-password: blank means "use my e-mail domain" (the server
// derives the tenant, e.g. jane@acme.com → acme).
export const optionalTenantSlug = z.string().trim().toLowerCase().regex(/^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)?$/, 'Use lowercase letters, digits and dashes.')

export const signInEmail = email

/**
 * The organisation's password rules for a new password: a fixed minimum, or a
 * getter returning the rules the server published (read at validation time,
 * so the schema follows rules that load after the form is created).
 */
export type PasswordRulesSource = number | (() => PasswordRequirements)

/** A new password: the organisation policy sets the rules; 8 characters is the platform floor. */
export const newPassword = (rules: PasswordRulesSource = PASSWORD_FLOOR.min_length) => {
  const get = typeof rules === 'number' ? () => ({ ...PASSWORD_FLOOR, min_length: rules }) : rules
  return z.string().superRefine((pw, ctx) => {
    const req = get()
    const broken = firstBroken(req, pw)
    if (broken) ctx.addIssue({ code: 'custom', message: ruleError(req, broken) })
  })
}

/** Two password fields that must match. */
export function withConfirm<T extends z.ZodRawShape>(shape: T, field: keyof T & string, confirm: keyof T & string) {
  return z.object(shape).refine((o) => (o as Record<string, unknown>)[field] === (o as Record<string, unknown>)[confirm], { path: [confirm], message: 'The passwords do not match.' })
}
