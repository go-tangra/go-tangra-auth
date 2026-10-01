import { computed, ref, watch, type Ref } from 'vue'
import { ApiError } from '@/api/client'
import { evaluate, parseRequirements, PASSWORD_FLOOR, refusalMessage, refusedRule, type PasswordRequirements, type PolicyRule } from '@/password/rules'

/**
 * Loads the organisation's password rules from the server (the single source
 * of truth) and tracks the live checklist for a password + confirmation pair.
 *
 * Until the rules arrive, or when they cannot be loaded, the platform floor is
 * shown; the server applies the real policy on submit either way. A refused
 * token (invitation or reset link no longer valid) sets `invalidToken`.
 */
export function usePasswordPolicy(load: () => Promise<unknown>, password: () => string, confirm: () => string) {
  const requirements = ref<PasswordRequirements>(PASSWORD_FLOOR)
  const loaded = ref(false)
  const invalidToken = ref(false)
  /** The rule the server named when it last refused the password. */
  const refused: Ref<PolicyRule | undefined> = ref()

  void (async () => {
    try {
      const r = parseRequirements(await load())
      if (r) {
        requirements.value = r
        loaded.value = true
      }
    } catch (err) {
      if (err instanceof ApiError && err.reason === 'invalid_token') invalidToken.value = true
    }
  })()

  const rules = computed(() => evaluate(requirements.value, password(), confirm()))
  const satisfied = computed(() => rules.value.every((r) => r.met))
  // Typing a new password clears the server's verdict on the previous one
  // (the form emptying the fields after a refusal keeps it on show).
  watch(password, (pw) => {
    if (pw !== '') refused.value = undefined
  })

  /**
   * Records a password_policy refusal and returns the field error naming the
   * failed rule; undefined for any other error.
   */
  function refusal(err: unknown): string | undefined {
    const msg = refusalMessage(requirements.value, err)
    if (msg !== undefined) refused.value = refusedRule(err)
    return msg
  }

  return { requirements, loaded, invalidToken, refused, rules, satisfied, refusal }
}
