import { z } from 'zod'
import { nonEmpty } from '@freya/ui/forms'

const redirectUri = z.string().trim().regex(/^https:\/\/|^http:\/\/(localhost|127\.0\.0\.1)/, 'Redirect URIs must be https (http only for localhost).')

/** Register an OAuth client; URIs are one per line. */
export const clientSchema = z.object({
  display_name: nonEmpty(100),
  redirect_uris: z.string().transform((s) => s.split('\n').map((u) => u.trim()).filter(Boolean)).pipe(z.array(redirectUri).min(1, 'Enter at least one redirect URI.').max(20)),
  public: z.boolean().optional().transform((v) => v ?? true),
})
export type ClientInput = z.output<typeof clientSchema>
