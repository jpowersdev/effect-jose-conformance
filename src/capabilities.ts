/**
 * Probes for Web Crypto features that vary by runtime, so tests can assert
 * the documented behaviour where a feature is missing instead of skipping.
 */
export const aes192Supported: Promise<boolean> = globalThis.crypto.subtle
  .importKey("raw", new Uint8Array(24), "AES-GCM", false, ["encrypt"])
  .then(() => true, () => false)

/** Whether an algorithm or encryption pair needs 192-bit AES. */
export const usesAes192 = (...names: ReadonlyArray<string>): boolean =>
  names.some((name) => name.includes("192"))
