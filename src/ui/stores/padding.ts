/**
 * Padding-scheme store. One signal: which padding scheme the run handler
 * + spec overlay uses. Persisted in localStorage so the user's pick
 * survives a reload — mirrors the byte-format store next door.
 *
 * Why not in the CipherSpec itself: the *result* of the choice (the
 * presence/absence of the pad/load/unpad/store leaves) does round-trip in
 * the spec, but the choice is a UI preference that re-applies to whichever
 * canonical spec is loaded for the current mode. Keeping it out of the spec
 * means switching encrypt↔decrypt doesn't lose the user's padding preference.
 *
 * Vocabulary: "none" | "pkcs7" | "zero-pad" | "iso7816-4". The select was
 * built extensibly for exactly this: adding a new scheme is a registry
 * entry + a row in `paddingLimits` + a label below.
 */

import type { PaddingScheme } from "@/core/spec-mutations";
import { createSignal } from "solid-js";
import { type Cipher, isAesCipher } from "./cipher";

const STORAGE_KEY = "cryptographer.paddingScheme";
const ALL_PADDING_SCHEMES: readonly PaddingScheme[] = ["none", "pkcs7", "zero-pad", "iso7816-4"];

const loadInitial = (): PaddingScheme => {
  // Same defensive shape as the format store — localStorage may be absent
  // (vitest node env) or denied (private mode), and we don't want
  // import-time to throw. Default to "none" so the FIPS-197 first-impression
  // matches today's behavior on fresh load.
  try {
    if (typeof localStorage === "undefined") return "none";
    const raw = localStorage.getItem(STORAGE_KEY);
    if (raw && (ALL_PADDING_SCHEMES as readonly string[]).includes(raw)) {
      return raw as PaddingScheme;
    }
  } catch {
    // Storage denied. Fall through to default.
  }
  return "none";
};

const [paddingScheme, setPaddingSchemeSignal] = createSignal<PaddingScheme>(loadInitial());

export const usePaddingScheme = () => paddingScheme;

export const setPaddingScheme = (scheme: PaddingScheme): void => {
  setPaddingSchemeSignal(scheme);
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.setItem(STORAGE_KEY, scheme);
    }
  } catch {
    // Persist failed; in-memory signal still updated.
  }
};

/** Re-export so callers don't have to import from two modules. */
export type { PaddingScheme };

/** Display labels for the selector. Keep in sync with `ALL_PADDING_SCHEMES`. */
export const PADDING_SCHEME_LABELS: Record<PaddingScheme, string> = {
  none: "none",
  pkcs7: "PKCS#7",
  "zero-pad": "Zero-pad",
  "iso7816-4": "ISO 7816-4",
};

export const PADDING_SCHEME_OPTIONS = ALL_PADDING_SCHEMES;

/**
 * Allowed raw input byte-length range for (mode, scheme, cipher). Used by
 * the Run handler to give a friendly error when the user's input is the
 * wrong size for single-block scope.
 *
 * AES-family (cipher.startsWith("aes-")):
 *   encrypt + none      → exactly 16 (today's behavior)
 *   encrypt + pkcs7     → 0..15  (PKCS#7 always adds ≥1 byte; 16 raw bytes
 *                                 would need a second padding block)
 *   encrypt + zero-pad  → 1..16  (zero-pad doesn't always pad, so 16 bytes
 *                                 fits in one block; length 0 is excluded
 *                                 because the formula gives N=0 there,
 *                                 producing a 0-byte block that fails
 *                                 load-block)
 *   encrypt + iso7816-4 → 0..15  (sentinel-byte-based; always adds ≥1 byte,
 *                                 same shape constraint as PKCS#7)
 *   decrypt + any       → exactly 16 (ciphertext is always one full block)
 *
 * Non-AES (today: Speck32/64): padding is not yet supported, so the input
 * is always exactly one cipher block — 4 bytes for Speck32/64 — regardless
 * of mode or the persisted padding choice. The padding selector is
 * disabled in the UI when a non-AES cipher is active.
 *
 * Multi-block modes would relax the upper bound; that's a separate phase.
 */
export const paddingLimits = (
  mode: "encrypt" | "decrypt",
  scheme: PaddingScheme,
  cipher: Cipher,
): { min: number; max: number } => {
  if (!isAesCipher(cipher)) {
    // Per-cipher fixed block size. Listed positively (not via a fallback)
    // so a future Speck64/128 PR that forgets to extend this switch fails
    // loud — throwing here is preferable to silently inheriting Speck32's
    // 4-byte cap and giving the user a "must be 4 bytes" error on an
    // 8-byte cipher.
    switch (cipher) {
      case "speck-32-64-be":
      case "speck-32-64-le":
        return { min: 4, max: 4 };
      default: {
        // Exhaustiveness check: if `Cipher` grows and this switch isn't
        // updated, TypeScript narrows `cipher` to `never` here and the
        // compile fails. At runtime, this is reached if the type lied to
        // us (cast through `any`, etc.); throwing is still the right call.
        const _exhaustive: never = cipher;
        throw new Error(`paddingLimits: unsupported non-AES cipher: ${_exhaustive as string}`);
      }
    }
  }
  if (mode === "decrypt") return { min: 16, max: 16 };
  switch (scheme) {
    case "none":
      return { min: 16, max: 16 };
    case "pkcs7":
      return { min: 0, max: 15 };
    case "zero-pad":
      return { min: 1, max: 16 };
    case "iso7816-4":
      return { min: 0, max: 15 };
  }
};

/** Test-only reset; production code never calls this. */
export const __resetPaddingForTests = (): void => {
  setPaddingSchemeSignal("none");
  try {
    if (typeof localStorage !== "undefined") {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // Ignore.
  }
};
