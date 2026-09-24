import { z } from 'zod'
import type { components } from '@/api/schema'

export type DirectoryConnection = components['schemas']['DirectoryConnection']
export type DirectoryTestResult = components['schemas']['TestResult']
const bounded = (max: number) => z.string().max(max, `At most ${max} characters.`)
const dn = bounded(1024).trim().min(1, 'Enter a distinguished name.')
const attribute = bounded(64).regex(/^([A-Za-z][A-Za-z0-9-]{0,63})?$/, 'Enter an LDAP attribute name.').optional()
const limit = (max: number) => z.preprocess(
  (v) => v === '' || v === undefined ? undefined : v,
  z.coerce.number().int(`Between 1 and ${max}.`).min(1, `Between 1 and ${max}.`).max(max, `Between 1 and ${max}.`).optional(),
)

export const directoryConnectionSchema = z.object({
  name: z.string().trim().min(1, 'Enter a name.').max(80, 'At most 80 characters.').refine((v) => !Array.from(v).some((c) => c.charCodeAt(0) < 32 || c.charCodeAt(0) === 127), 'Control characters are not allowed.'),
  kind: z.enum(['active_directory', 'openldap', 'other']),
  url: bounded(512).trim().refine((v) => {
    try {
      const u = new URL(v)
      return ['ldap:', 'ldaps:'].includes(u.protocol) && !!u.hostname && !u.username && !u.password && !u.pathname && !u.search && !u.hash
    } catch { return false }
  }, 'Enter an ldap:// or ldaps:// URL.'),
  tls_mode: z.enum(['ldaps', 'starttls', 'plain']),
  allow_tls12: z.boolean().default(false),
  ca_pem: bounded(65536).optional(),
  bind_dn: dn,
  // Never trim a secret; only the empty string means keep the stored password.
  bind_password: z.preprocess((v) => v === '' ? undefined : v, bounded(1024).optional()),
  base_dn: dn,
  base_filter: bounded(4096).optional(),
  attributes: z.object({ uid: attribute, email: attribute, display_name: attribute, first_name: attribute, last_name: attribute }).optional(),
  size_limit: limit(1000),
  time_limit_seconds: limit(60),
})
export const directoryCreateSchema = directoryConnectionSchema.refine((v) => !!v.bind_password, { path: ['bind_password'], message: 'Enter the bind password.' })
export type DirectoryInput = z.output<typeof directoryConnectionSchema>

const optionalTrimmed = (value: unknown) => typeof value === 'string' ? value.trim() || undefined : value
export const directorySearchSchema = z.object({
  filter: z.preprocess(optionalTrimmed, bounded(4096).optional()),
  base: z.preprocess(optionalTrimmed, bounded(1024).optional()),
  scope: z.preprocess(optionalTrimmed, z.enum(['one', 'sub']).optional()),
})
export const directoryImportSchema = z.object({
  uids: z.array(z.string().min(1)).min(1, 'Select at least one person.').max(500, 'Select at most 500 people.').refine((uids) => new Set(uids).size === uids.length, 'Select each person only once.'),
})
export type DirectorySearchInput = z.output<typeof directorySearchSchema>
export type DirectorySearchResult = components['schemas']['SearchResult']
export type DirectoryImportResult = components['schemas']['ImportResult']
