import { z } from 'zod'
import { signInEmail, optionalTenantSlug, newPassword, withConfirm } from './common'

export const forgotSchema = z.object({ tenant: optionalTenantSlug, email: signInEmail })
export const resetSchema = (min = 8) => withConfirm({ password: newPassword(min), confirm: z.string() }, 'password', 'confirm')
