import { z } from 'zod'
import { signInEmail, optionalTenantSlug, newPassword, withConfirm, type PasswordRulesSource } from './common'

export const forgotSchema = z.object({ tenant: optionalTenantSlug, email: signInEmail })
export const resetSchema = (rules?: PasswordRulesSource) => withConfirm({ password: newPassword(rules), confirm: z.string() }, 'password', 'confirm')
