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

/** Maps a refusal reason to a sentence for administrators. */
export function reasonMessage(reason: string): string {
  switch (reason) {
    case 'last_owner':
      return 'The last owner of an organisation cannot be removed or demoted.'
    case 'self_escalation':
      return 'You can only grant permissions you hold yourself.'
    case 'forbidden':
      return 'You do not have permission to do that.'
    case 'not_found':
      return 'That record does not exist in your organisation.'
    case 'validation_failed':
      return 'Please check the values you entered.'
    case 'password_policy':
      return 'The password does not meet the organisation policy.'
    case 'invalid_token':
      return 'This invitation link is invalid or has expired.'
    case 'name_taken':
      return 'A group with that name already exists.'
    case 'member_count_mismatch':
      return 'The group changed while you were looking at it. Reload and try again.'
    case 'owner_via_group':
      return 'The owner role can only be assigned to people directly.'
    case 'unsupported_type':
      return 'Use a PNG, JPEG or WebP picture.'
    case 'too_large_dimensions':
      return 'The picture is too large; use one under 4096 × 4096 pixels.'
    case 'not_an_image':
    case 'decode_failed':
      return 'That file could not be read as a picture.'
    case 'body_too_large':
      return 'The file is too large (2 MB at most).'
    case 'rate_limited':
      return 'Too many requests; please wait a moment.'
    default:
      return 'The request could not be completed.'
  }
}
