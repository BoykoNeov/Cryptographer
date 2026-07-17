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
 *
 * Session-only (2026-05-19): not persisted in localStorage. Refresh resets
 * to "single-block". See the matching note in cipher.ts — both selectors
 * were demoted to session-scope together so refresh equals a clean slate
 * (matching the inputs, which were never persisted either) instead of
 * leaving a half-persistent UI state on reload.
 */

import { createSignal } from "solid-js";
import type { Cipher } from "./cipher";

export type CipherMode = "single-block" | "ecb" | "cbc" | "ctr";

// Phase 1 shipped ECB; Phase 2 ships CBC; CTR arrives in Phase 3. The
// dropdown shows all four entries but disables the unsupported ones so
// the eventual rollout doesn't move things around in the UI.
export const SUPPORTED_CIPHER_MODES: readonly CipherMode[] = ["single-block", "ecb", "cbc"];

/**
 * Which (cipher, cipherMode) combinations have a concrete spec in
 * `stores/spec.ts`'s defaults table.
 *
 * Used both by the App's dropdown (to disable unsupported (cipher, mode)
 * options so the user can't pick a combo that silently falls back to
 * single-block) and by `setCipher` in spec.ts (to reset cipherMode when
 * the user switches to a cipher that doesn't support the active mode).
 *
 * If this drifts from the actual defaults table, the dropdown will lie —
 * keep them in sync when registering a new mode factory.
 * `tests/cipher-mode-fallback.test.ts` is the canary.
 */
export const SUPPORTED_CIPHER_MODES_BY_CIPHER: Readonly<Record<Cipher, readonly CipherMode[]>> = {
  // The AES variants: every one has a `BlockCipherCore`, and the generic mode
  // builders generate their ECB/CBC specs from it (`stores/spec.ts`).
  "aes-128": ["single-block", "ecb", "cbc"],
  "aes-192": ["single-block", "ecb", "cbc"],
  "aes-256": ["single-block", "ecb", "cbc"],
  // Everything below is single-block for ONE reason: no `BlockCipherCore` yet.
  // A core needs the cipher's body to accept its block from an arbitrary port
  // rather than hardcoding `$input` — the per-cipher seed-threading work that
  // `docs/plans/foamy-prancing-wren.md` Phase C templates on Blowfish. It is
  // NOT a block-size limitation: the mode builders, the iterate, and the
  // padding overlay are all block-size-generic as of Phase B.
  "speck-32-64-be": ["single-block"],
  "speck-32-64-le": ["single-block"],
  "serpent-128": ["single-block"],
  "serpent-192": ["single-block"],
  "serpent-256": ["single-block"],
  des: ["single-block"],
  blowfish: ["single-block"],
  twofish: ["single-block"],
};

export const isCipherModeSupported = (cipher: Cipher, mode: CipherMode): boolean =>
  (SUPPORTED_CIPHER_MODES_BY_CIPHER[cipher] as readonly string[]).includes(mode);

// Default to single-block so the first impression remains the FIPS-197
// Appendix C.1 round-by-round demo. Session-only — see file header.
const [cipherMode, setCipherModeSignal] = createSignal<CipherMode>("single-block");

export const useCipherMode = () => cipherMode;

export const setCipherMode = (m: CipherMode): void => {
  setCipherModeSignal(m);
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
};
