import { describeReason, registerReasons } from '@go-tangra/ui/forms'

// Module roles and module-scoped permissions (feature 019, contracts/http.md).
registerReasons({
  managed_role: 'Module roles are managed by their module; clone it to customise.',
  role_retired: 'That role is no longer provided by its module and cannot be newly assigned.',
})

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
  'module_registered',
  'module_role_upserted',
  'module_role_retired',
  'role_cloned',
  'permission_migrated',
  'permission_pruned',
] as const

export type AuditEventType = (typeof auditEventTypes)[number]

/** Human labels for the audit event filter and trail. */
export const auditEventLabels: Record<AuditEventType, string> = {
  signin_ok: 'Signed in',
  signin_failed: 'Sign-in failed',
  lockout: 'Account locked',
  signout: 'Signed out',
  mfa_enrolled: 'Second factor enrolled',
  mfa_removed: 'Second factor removed',
  recovery_codes_regenerated: 'Recovery codes regenerated',
  password_changed: 'Password changed',
  recovery_requested: 'Recovery requested',
  recovery_completed: 'Recovery completed',
  invite_created: 'Invitation created',
  invite_accepted: 'Invitation accepted',
  invite_revoked: 'Invitation revoked',
  role_created: 'Role created',
  role_updated: 'Role updated',
  role_deleted: 'Role removed',
  role_assigned: 'Role assigned',
  role_revoked: 'Role revoked',
  permission_registered: 'Permissions registered',
  user_deactivated: 'User deactivated',
  user_reactivated: 'User reactivated',
  session_revoked: 'Session revoked',
  tenant_created: 'Organisation created',
  tenant_suspended: 'Organisation suspended',
  tenant_reactivated: 'Organisation reactivated',
  operator_grant_created: 'Operator grant created',
  operator_grant_used: 'Operator grant used',
  client_registered: 'Client registered',
  policy_updated: 'Policy updated',
  cross_tenant_refused: 'Cross-organisation access refused',
  authz_denied: 'Access denied',
  module_registered: 'Module registered',
  module_role_upserted: 'Module role updated',
  module_role_retired: 'Module role retired',
  role_cloned: 'Role cloned',
  permission_migrated: 'Permissions migrated to modules',
  permission_pruned: 'Legacy permissions pruned',
}

/** Label for an audit event type; unknown types are shown as sent. */
export const auditEventLabel = (t: string): string => (auditEventLabels as Record<string, string>)[t] ?? t

export const userStatuses = ['invited', 'active', 'deactivated', 'imported'] as const

/** Maps a refusal reason to a sentence for administrators (the kit's vocabulary plus the console's, registered in api/client.ts). */
export function reasonMessage(reason: string): string {
  return describeReason(reason)
}
