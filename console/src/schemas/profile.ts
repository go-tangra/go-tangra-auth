import { z } from 'zod'
import { optionalString } from '@go-tangra/ui/forms'

export const profileSchema = z.object({
  first_name: optionalString(100),
  last_name: optionalString(100),
  phone: optionalString(24).pipe(z.string().regex(/^\+?[0-9 ().-]{7,24}$/, 'Use the international format, e.g. +385 91 123 4567').optional()),
  display_name: optionalString(100),
})
export type ProfileInput = z.output<typeof profileSchema>

export const AVATAR_TYPES = ['image/png', 'image/jpeg', 'image/webp'] as const
export const AVATAR_MAX_BYTES = 2 * 1024 * 1024
export const avatarSchema = z.instanceof(File).refine((f) => (AVATAR_TYPES as readonly string[]).includes(f.type), 'Use a PNG, JPEG or WebP picture.').refine((f) => f.size <= AVATAR_MAX_BYTES, 'The file is too large (2 MB at most).')
