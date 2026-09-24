import { z } from 'zod'
import { nonEmpty } from '@go-tangra/ui/forms'
import { newPassword, withConfirm } from './common'

export const acceptInvitationSchema = (min = 8) =>
  withConfirm({ display_name: nonEmpty(100), password: newPassword(min), confirm: z.string() }, 'password', 'confirm')
export type AcceptInvitationInput = z.output<ReturnType<typeof acceptInvitationSchema>>
