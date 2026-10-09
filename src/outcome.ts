/** The observable result of an operation, normalized across both libraries. */
export type Outcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: string }

/**
 * The jose error code equivalent to each effect/jose error tag.
 *
 * jose throws `TypeError` for key misuse; effect/jose fails with
 * `InvalidKeyError`, so both are reported as "TypeError".
 */
export const joseCodeFor: Readonly<Record<string, string>> = {
  MalformedJwsError: "ERR_JWS_INVALID",
  SignatureVerificationError: "ERR_JWS_SIGNATURE_VERIFICATION_FAILED",
  UnsupportedJwsHeaderError: "ERR_JOSE_NOT_SUPPORTED",
  MalformedJweError: "ERR_JWE_INVALID",
  DecryptionError: "ERR_JWE_DECRYPTION_FAILED",
  UnsupportedJweHeaderError: "ERR_JOSE_NOT_SUPPORTED",
  MalformedJwtError: "ERR_JWT_INVALID",
  ClaimValidationError: "ERR_JWT_CLAIM_VALIDATION_FAILED",
  TokenExpiredError: "ERR_JWT_EXPIRED",
  AlgorithmNotAllowedError: "ERR_JOSE_ALG_NOT_ALLOWED",
  UnsupportedAlgorithmError: "ERR_JOSE_NOT_SUPPORTED",
  UnsupportedKeyError: "ERR_JOSE_NOT_SUPPORTED",
  InvalidKeyError: "TypeError",
  MalformedKeyError: "ERR_JWK_INVALID",
  MalformedKeySetError: "ERR_JWKS_INVALID",
  NoMatchingKeyError: "ERR_JWKS_NO_MATCHING_KEY",
  MultipleMatchingKeysError: "ERR_JWKS_MULTIPLE_MATCHING_KEYS",
  KeySetFetchError: "ERR_JOSE_GENERIC",
  KeySetTimeoutError: "ERR_JWKS_TIMEOUT"
}

const tagOf = (e: unknown): string | undefined => {
  const tag = (e as { _tag?: unknown } | null)?._tag
  return typeof tag === "string" ? tag : undefined
}

/**
 * Settles either library's promise into an `Outcome`. effect/jose failures
 * are translated through `joseCodeFor`; defects such as `TypeError` and jose's
 * own errors are reported by their `code` or class.
 */
export const settle = async (promise: Promise<unknown>): Promise<Outcome> => {
  try {
    await promise
    return { ok: true }
  } catch (e) {
    const tag = tagOf(e)
    if (tag !== undefined) return { ok: false, code: joseCodeFor[tag] ?? tag }
    if (e instanceof TypeError) return { ok: false, code: "TypeError" }
    const code = (e as { code?: unknown })?.code
    if (typeof code === "string") return { ok: false, code }
    return { ok: false, code: `Unexpected(${String(e)})` }
  }
}

/** Settles an effect/jose promise into the failure's tag, for asserting exact error types. */
export const tagged = async (promise: Promise<unknown>): Promise<string> => {
  try {
    await promise
    return "Success"
  } catch (e) {
    return tagOf(e) ?? (e instanceof Error ? e.constructor.name : String(e))
  }
}
