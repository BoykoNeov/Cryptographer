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
 * Today's vocabulary is "none" | "pkcs7". The select is built to extend:
 * "zero-pad" and "iso7816-4" arrive in a follow-up commit; both are
 * additional registry+helper entries, not a refactor.
 */

import type { PaddingScheme } from "@/core/spec-mutations";
import { createSignal } from "solid-js";

const STORAGE_KEY = "cryptographer.paddingScheme";
const ALL_PADDING_SCHEMES: readonly PaddingScheme[] = ["none", "pkcs7"];

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
};

export const PADDING_SCHEME_OPTIONS = ALL_PADDING_SCHEMES;

/**
 * Allowed raw input byte-length range for (mode, scheme). Used by the Run
 * handler to give a friendly error when the user's input is the wrong size
 * for single-block scope.
 *
 *   encrypt + none   → exactly 16 (today's behavior)
 *   encrypt + pkcs7  → 0..15 (PKCS#7 always adds ≥1 byte; 16 raw bytes
 *                             would need a second padding block, which
 *                             requires multi-block modes)
 *   decrypt + any    → exactly 16 (ciphertext is always one full block)
 *
 * Future schemes will register their own ranges here.
 */
export const paddingLimits = (
  mode: "encrypt" | "decrypt",
  scheme: PaddingScheme,
): { min: number; max: number } => {
  if (mode === "decrypt") return { min: 16, max: 16 };
  switch (scheme) {
    case "none":
      return { min: 16, max: 16 };
    case "pkcs7":
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
