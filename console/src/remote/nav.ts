/** Dynamic navigation entries (none: authmanifest declares static entries,
 * including permission-gated Directories at /console/admin/directories). */
export interface NavEntry {
  title: string
  path: string
  icon?: string
  order: number
}

export function nav(): NavEntry[] {
  return []
}
export default nav
