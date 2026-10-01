import { z } from 'zod'
import { nonEmpty } from '@go-tangra/ui/forms'
import { newPassword, withConfirm, type PasswordRulesSource } from './common'

export const acceptInvitationSchema = (rules?: PasswordRulesSource) =>
  withConfirm({ display_name: nonEmpty(100), password: newPassword(rules), confirm: z.string() }, 'password', 'confirm')
export type AcceptInvitationInput = z.output<ReturnType<typeof acceptInvitationSchema>>
