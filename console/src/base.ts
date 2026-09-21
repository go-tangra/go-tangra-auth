/**
 * Where the console lives. Standalone (edge mode) the SPA is served under
 * /console/ by its own router; as a federated remote inside the platform shell
 * the same routes are mounted under /console by the shell's router.
 */
export const isRemote = import.meta.env.VITE_REMOTE === '1'
export const basePath = isRemote ? '/console' : ''

/** Prefixes an in-console path with the base when running as a remote. */
export function consolePath(p: string): string {
  return basePath + p
}

/** True when the auth service runs behind the platform gateway (a shell owns "/"). */
export function gatewayMode(): boolean {
  return document.querySelector<HTMLMetaElement>('meta[name="freya-gateway"]')?.content === '1'
}

/**
 * Navigates after sign-in or enrolment. Targets under /console are console
 * pages (router-relative in the standalone build, absolute in the remote);
 * behind the gateway every other target belongs to the platform shell and
 * needs a full navigation; standalone, the console router handles them.
 */
export async function leaveTo(navigate: (to: string) => Promise<unknown>, target: string): Promise<void> {
  if (target.startsWith('/console')) {
    await navigate(isRemote ? target : target.slice('/console'.length) || '/')
    return
  }
  if (gatewayMode() || target.startsWith('/authorize')) {
    window.location.assign(target)
    return
  }
  await navigate(target)
}

/** Builds a `next` value for the sign-in page from a console-relative path. */
export function consoleNext(fullPath: string): string {
  return gatewayMode() && !isRemote ? '/console' + fullPath : fullPath
}
