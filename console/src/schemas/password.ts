import { z } from 'zod'
import { newPassword, withConfirm } from './common'

export const changePasswordSchema = (min = 8) =>
  withConfirm({ current_password: z.string().min(1, 'Enter your current password.'), new_password: newPassword(min), confirm: z.string() }, 'new_password', 'confirm')
