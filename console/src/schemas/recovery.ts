import { z } from 'zod'
import { signInEmail, tenantSlug, newPassword, withConfirm } from './common'

export const forgotSchema = z.object({ tenant: tenantSlug, email: signInEmail })
export const resetSchema = (min = 8) => withConfirm({ password: newPassword(min), confirm: z.string() }, 'password', 'confirm')
