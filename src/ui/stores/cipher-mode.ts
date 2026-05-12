/**
 * Cipher-mode store. Holds which block-cipher mode of operation the active
 * AES spec runs in:
 *
 *   "single-block" — today's path; the input is exactly one 16-byte block
 *                    and the canonical FIPS-197 spec runs as-is. Selected
 *                    by default on fresh load so the first impression
 *                    remains the FIPS-197 Appendix C.1 round-by-round demo.
 *   "ecb"          — multi-block, no chaining. Each block encrypts
 *                    independently. The "what NOT to do" baseline.
 *   "cbc"          — multi-block with IV-driven block chaining. Phase 2.
 *   "ctr"          — keystream from encrypting a counter; XORed with
 *                    plaintext, no padding. Phase 3.
 *
 * Orthogonal to:
 *   - direction ("encrypt"/"decrypt"), held by stores/spec.ts
 *   - cipher variant ("aes-128"/etc.), held by stores/cipher.ts
 *   - padding scheme, held by stores/padding.ts
 *   - IV bytes (Phase 2), held by stores/iv.ts
 *
 * The mode + cipher + direction triple selects one canonical spec from
 * the table in stores/spec.ts; padding overlay layers on top of that.
 *
 * Non-AES ciphers (Speck32/64) only support "single-block" today — the
 * cipher-mode <select> is greyed out when a Speck variant is active.
 */

import { createSignal } from "solid-js";

export type CipherMode = "single-block" | "ecb" | "cbc" | "ctr";

const ALL_CIPHER_MODES: readonly CipherMode[] = ["single-block", "ecb", "cbc", "ctr"];

// Phase 1 ships ECB; CBC + CTR arrive in later phases. The dropdown shows
// all four entries but disables the unsupported ones so the eventual
// rollout doesn't move things around in the UI.
export const SUPPORTED_CIPHER_MODES: readonly CipherMode[] = ["single-block", "ecb"];

const STORAGE_KEY = "cryptographer.cipherMode";

const loadInitial = (): CipherMode => {
  try {
    if (typeof localStorage === "undefined") return "single-block";
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw && (ALL_CIPHER_MODES as readonly string[]).includes(raw)) {
      const m = raw as CipherMode;
      // If the persisted value is a phase that hasn't shipped yet, fall
      // back to the safest mode so the app doesn't crash on load.
      if (!(SUPPORTED_CIPHER_MODES as readonly string[]).includes(m)) return "single-block";
      return m;
    }
  } catch {
    // Storage denied; fall through.
  }
  return "single-block";
};

const [cipherMode, setCipherModeSignal] = createSignal<CipherMode>(loadInitial());

export const useCipherMode = () => cipherMode;

export const setCipherMode = (m: CipherMode): void => {
  setCipherModeSignal(m);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, m);
    }
  } catch {
    // Persist failed; signal still updated.
  }
};

/** Human-readable labels for the cipher-mode <select>. */
export const CIPHER_MODE_LABELS: Record<CipherMode, string> = {
  "single-block": "single block",
  ecb: "ECB",
  cbc: "CBC",
  ctr: "CTR",
};

/** Test-only reset; production code uses setCipherMode. */
export const __resetCipherModeForTests = (): void => {
  setCipherModeSignal("single-block");
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
