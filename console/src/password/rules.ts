// Password requirements as the server publishes them (PasswordRequirements in
// api/openapi/console.yaml). The server's policy is the single source of
// truth: the console only mirrors it to guide the person while they type, and
// the server validates again on submit.
import { ApiError } from '@/api/client'
import type { components } from '@/api/schema'

export type PasswordRequirements = components['schemas']['PasswordRequirements']
/** A server rule (the keys of PasswordRequirements) or the console's own confirmation match. */
export type PolicyRule = 'min_length' | 'max_length' | 'reject_trivial'
export type RuleKey = PolicyRule | 'match'

export interface RuleState {
  key: RuleKey
  label: string
  met: boolean
}

/**
 * The platform floor, used until (or if) the organisation's rules cannot be
 * loaded; the server still applies the real policy on submit.
 */
export const PASSWORD_FLOOR: PasswordRequirements = { min_length: 8, max_length: 1024, reject_trivial: true }

const POLICY_RULES: readonly PolicyRule[] = ['min_length', 'max_length', 'reject_trivial']

/** Accepts a well-formed PasswordRequirements response, otherwise undefined. */
export function parseRequirements(v: unknown): PasswordRequirements | undefined {
  if (typeof v !== 'object' || v === null) return undefined
  const r = v as Record<string, unknown>
  const int = (x: unknown): x is number => typeof x === 'number' && Number.isInteger(x) && x > 0
  if (!int(r.min_length) || !int(r.max_length) || r.min_length > r.max_length || typeof r.reject_trivial !== 'boolean') return undefined
  return { min_length: r.min_length, max_length: r.max_length, reject_trivial: r.reject_trivial }
}

/** Length as the server counts it: Unicode code points, not UTF-16 units. */
export const codePoints = (s: string): number => Array.from(s).length

/** Blank, or one character repeated (the server's reject_trivial rule). */
export function isTrivial(pw: string): boolean {
  if (pw.trim() === '') return true
  const first = pw.codePointAt(0)
  return Array.from(pw).every((c) => c.codePointAt(0) === first)
}

/** Short checklist wording for each rule. */
export function ruleLabel(req: PasswordRequirements, key: RuleKey): string {
  switch (key) {
    case 'min_length':
      return `At least ${req.min_length} characters`
    case 'max_length':
      return `No more than ${req.max_length} characters`
    case 'reject_trivial':
      return 'Not blank or a single repeated character'
    case 'match':
      return 'Both passwords match'
  }
}

/** Whether pw meets one server rule. */
export function meets(req: PasswordRequirements, key: PolicyRule, pw: string): boolean {
  switch (key) {
    case 'min_length':
      return codePoints(pw) >= req.min_length
    case 'max_length':
      return codePoints(pw) <= req.max_length
    case 'reject_trivial':
      return !req.reject_trivial || !isTrivial(pw)
  }
}

/** The first server rule pw breaks, in the order the server checks them. */
export function firstBroken(req: PasswordRequirements, pw: string): PolicyRule | undefined {
  return (['max_length', 'min_length', 'reject_trivial'] as const).find((k) => !meets(req, k, pw))
}

/** Field error text for a broken rule. */
export function ruleError(req: PasswordRequirements, key: PolicyRule): string {
  switch (key) {
    case 'min_length':
      return `At least ${req.min_length} characters.`
    case 'max_length':
      return `At most ${req.max_length} characters.`
    case 'reject_trivial':
      return 'Must not be blank or a single repeated character.'
  }
}

/**
 * The checklist for pw. With a confirmation value the match rule is included;
 * it is only met once both fields hold the same non-empty password.
 */
export function evaluate(req: PasswordRequirements, pw: string, confirm?: string): RuleState[] {
  const rules: RuleState[] = POLICY_RULES.filter((k) => k !== 'reject_trivial' || req.reject_trivial).map((key) => ({ key, label: ruleLabel(req, key), met: meets(req, key, pw) }))
  if (confirm !== undefined) rules.push({ key: 'match', label: ruleLabel(req, 'match'), met: pw !== '' && pw === confirm })
  return rules
}

/** A one-line summary of the rules (the password field's description). */
export function summary(req: PasswordRequirements): string {
  const parts = [`${req.min_length} to ${req.max_length} characters`]
  if (req.reject_trivial) parts.push('not blank or a single repeated character')
  return `Use ${parts.join(', ')}.`
}

/**
 * The rule a server refusal names: reason password_policy with detail.rule.
 * Undefined for any other error (or a refusal without a known rule).
 */
export function refusedRule(err: unknown): PolicyRule | undefined {
  if (!(err instanceof ApiError) || err.reason !== 'password_policy') return undefined
  const rule = err.detail?.rule
  return typeof rule === 'string' && (POLICY_RULES as readonly string[]).includes(rule) ? (rule as PolicyRule) : undefined
}

/** Field error for a server refusal (never echoes the password). */
export function refusalMessage(req: PasswordRequirements, err: unknown): string | undefined {
  if (!(err instanceof ApiError) || err.reason !== 'password_policy') return undefined
  const rule = refusedRule(err)
  return rule ? `The organisation's policy refused this password: ${ruleError(req, rule).replace(/^./, (c) => c.toLowerCase())}` : 'The password does not meet the organisation policy.'
}
