import { JoseError } from "effect/jose"

/** The observable result of an operation, normalized across both libraries. */
export type Outcome =
  | { readonly ok: true }
  | { readonly ok: false; readonly code: string }

/**
 * jose throws `JOSEError` subclasses carrying `code`, and `TypeError` for key
 * misuse and invalid arguments. effect/jose fails with `JoseError`, whose
 * `code` is `undefined` for the equivalent reasons, which we report as
 * "TypeError" so the two can be compared.
 */
export const settle = async (promise: Promise<unknown>): Promise<Outcome> => {
  try {
    await promise
    return { ok: true }
  } catch (e) {
    if (JoseError.isJoseError(e)) return { ok: false, code: e.code ?? "TypeError" }
    if (e instanceof TypeError) return { ok: false, code: "TypeError" }
    const code = (e as { code?: unknown })?.code
    if (typeof code === "string") return { ok: false, code }
    return { ok: false, code: `Unexpected(${String(e)})` }
  }
}
