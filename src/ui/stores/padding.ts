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
import type { CipherMode } from "./cipher-mode";

/**
 * UI cap on multi-block input length, in *blocks*. Real ciphers have no
 * such limit — this is purely so the trace scrubber stays browsable.
 * `MAX_BLOCKS_UI × 16` bytes ⇒ on the order of (frames-per-block × N)
 * trace frames; at 16 blocks for AES-128, that's ~1600 frames, still
 * navigable. Bumping this is a one-line change if a user wants to encrypt
 * a paragraph; just be aware the slider degrades visually.
 */
export const MAX_BLOCKS_UI = 16;

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
 * Allowed raw input byte-length range for (mode, scheme, cipher, cipherMode).
 * Used by the Run handler to give a friendly error when the user's input is
 * the wrong size.
 *
 * Three families of behavior:
 *
 *   • Non-AES (Speck32/64): one fixed-size block, regardless of mode or
 *     padding choice. The padding selector is disabled in the UI.
 *
 *   • AES single-block: today's behavior — exactly 16 bytes on decrypt,
 *     0..15 / 1..16 / 16..16 on encrypt depending on padding scheme.
 *
 *   • AES multi-block (ECB / CBC): input is N × 16 bytes (any whole
 *     number of blocks up to MAX_BLOCKS_UI). PKCS#7 / zero-pad /
 *     iso7816-4 each take 0..MAX_BLOCKS_UI × 16 on encrypt (their pad
 *     step expands to the next block boundary). On decrypt, input must
 *     be a clean multiple of 16, 16..MAX_BLOCKS_UI × 16.
 *
 *   • AES CTR (Phase 3): no padding, any length 0..MAX_BLOCKS_UI × 16.
 *     The keystream is truncated to the original length.
 */
export const paddingLimits = (
  mode: "encrypt" | "decrypt",
  scheme: PaddingScheme,
  cipher: Cipher,
  cipherMode: CipherMode = "single-block",
): { min: number; max: number } => {
  if (!isAesCipher(cipher)) {
    switch (cipher) {
      case "speck-32-64-be":
      case "speck-32-64-le":
        return { min: 4, max: 4 };
      // Serpent uses 16-byte blocks like AES, but the padding overlay
      // (`load-block`/`store-block`) is hardcoded for MatrixState and our
      // Serpent specs use BytesState — so today the padding selector is
      // disabled for Serpent and the input is required to be exactly one
      // block. A future block-size-aware load/store rework can unlock the
      // overlay for both Speck and Serpent simultaneously.
      case "serpent-128":
      case "serpent-192":
      case "serpent-256":
        return { min: 16, max: 16 };
      // DES — single 64-bit block. Like Speck and Serpent, the padding
      // overlay's load-block step is 16-byte-only, so the padding selector
      // is disabled and the input is fixed at one block. A future block-
      // size-aware load/store would unlock multi-block DES (and ECB/CBC).
      case "des":
        return { min: 8, max: 8 };
      // Blowfish — single 64-bit block. Same padding-overlay blocker as
      // Speck/Serpent/DES (load-block is 16-byte-only), so the input is fixed
      // at exactly one 8-byte block and the padding selector is disabled.
      case "blowfish":
        return { min: 8, max: 8 };
      default: {
        const _exhaustive: never = cipher;
        throw new Error(`paddingLimits: unsupported non-AES cipher: ${_exhaustive as string}`);
      }
    }
  }

  const MAX_BYTES = MAX_BLOCKS_UI * 16;

  // ── AES multi-block (ECB / CBC) ─────────────────────────────────────────
  if (cipherMode === "ecb" || cipherMode === "cbc") {
    if (mode === "decrypt") {
      // Decrypt input must be a clean ciphertext block multiple. The Run
      // handler also checks `length % 16 === 0`; this just bounds the
      // overall range. min=16 because we need at least one block to act on.
      return { min: 16, max: MAX_BYTES };
    }
    // Encrypt: every padding scheme produces a clean multi-block output;
    // the pad step itself enforces its scheme-specific invariants on
    // shorter inputs. The UI just caps the overall length.
    switch (scheme) {
      case "none":
        // Same as today's single-block "none" but extended to multi-block:
        // input must already be a multiple of 16. The Run handler checks
        // alignment; we bound the range.
        return { min: 16, max: MAX_BYTES };
      case "pkcs7":
      case "iso7816-4":
        // Always-adds-≥1-byte schemes: encrypt of `MAX_BYTES` bytes would
        // append a full extra padding block, going past the UI cap. So
        // top out at MAX_BYTES - 1 so the padded result stays ≤ MAX_BYTES.
        return { min: 0, max: MAX_BYTES - 1 };
      case "zero-pad":
        // Zero-pad is the one scheme that doesn't always add a byte: input
        // length already a multiple of 16 produces no extra padding. So
        // it can use the full range — except length 0, which would yield
        // a 0-byte input (no blocks to iterate).
        return { min: 1, max: MAX_BYTES };
    }
  }

  // ── AES CTR (Phase 3) ───────────────────────────────────────────────────
  // CTR doesn't use the padding overlay (no padding needed; the keystream
  // is truncated to plaintext length). The byte-length range is purely the
  // UI cap. Same on encrypt and decrypt (CTR is symmetric).
  if (cipherMode === "ctr") {
    return { min: 0, max: MAX_BYTES };
  }

  // ── AES single-block ───────────────────────────────────────────────────
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
