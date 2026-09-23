import { z } from 'zod'
import { isoDate } from '@freya/ui/forms'
import { auditEventTypes } from '@/api/vocab'

export const auditFilterSchema = z.object({
  event_type: z.enum(auditEventTypes).optional(),
  user_id: z.string().trim().max(64).optional(),
  from: isoDate,
  to: isoDate,
})
