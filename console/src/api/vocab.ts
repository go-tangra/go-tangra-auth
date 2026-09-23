import { describeReason } from '@freya/ui/forms'

/** Closed vocabulary of application audit events (data-model.md). */
export const auditEventTypes = [
  'signin_ok',
  'signin_failed',
  'lockout',
  'signout',
  'mfa_enrolled',
  'mfa_removed',
  'recovery_codes_regenerated',
  'password_changed',
  'recovery_requested',
  'recovery_completed',
  'invite_created',
  'invite_accepted',
  'invite_revoked',
  'role_created',
  'role_updated',
  'role_deleted',
  'role_assigned',
  'role_revoked',
  'permission_registered',
  'user_deactivated',
  'user_reactivated',
  'session_revoked',
  'tenant_created',
  'tenant_suspended',
  'tenant_reactivated',
  'operator_grant_created',
  'operator_grant_used',
  'client_registered',
  'policy_updated',
  'cross_tenant_refused',
  'authz_denied',
] as const

export type AuditEventType = (typeof auditEventTypes)[number]

export const userStatuses = ['invited', 'active', 'deactivated'] as const

/** Maps a refusal reason to a sentence for administrators (the kit's vocabulary plus the console's, registered in api/client.ts). */
export function reasonMessage(reason: string): string {
  return describeReason(reason)
}
