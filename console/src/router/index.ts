import { createRouter, createWebHistory } from 'vue-router'
import { useSession } from '@/stores/session'
import { consoleNext } from '@/base'
import { routes } from './routes'

export { routes }

export const router = createRouter({ history: createWebHistory('/console/'), routes })

router.beforeEach(async (to) => {
  const session = useSession()
  if (session.status === 'unknown') await session.load()
  if (session.status === 'outage' && to.name !== 'outage') return { name: 'outage' }
  if (to.meta.public) return true
  if (!session.signedIn) return { name: 'signin', query: { next: consoleNext(to.fullPath) } }
  // Tenants that require a second factor gate the whole console behind enrolment.
  if (session.mfaSetupRequired && to.name !== 'mfa-enrol') return { name: 'mfa-enrol' }
  if (to.meta.operator && !session.operator) return { name: 'forbidden' }
  if (to.meta.roles && !session.hasAnyRole(to.meta.roles)) return { name: 'forbidden' }
  return true
})
