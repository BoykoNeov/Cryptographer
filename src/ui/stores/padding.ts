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
import { blockCipherCoreFor } from "./block-cipher-cores";
import type { Cipher } from "./cipher";
import type { CipherMode } from "./cipher-mode";

/**
 * UI cap on multi-block input length, in *blocks*. Real ciphers have no
 * such limit — this is purely so the trace scrubber stays browsable.
 * `MAX_BLOCKS_UI × blockByteLength` bytes ⇒ on the order of
 * (frames-per-block × N) trace frames; at 16 blocks for AES-128, that's
 * ~1600 frames, still navigable. Bumping this is a one-line change if a user
 * wants to encrypt a paragraph; just be aware the slider degrades visually.
 *
 * Counted in BLOCKS, not bytes, on purpose: the thing that degrades is frame
 * count, which scales with blocks. A cipher with a smaller block therefore
 * gets a smaller byte cap for the same trace weight.
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
 * Fixed one-block input size for a cipher with no `BlockCipherCore`.
 *
 * This switch is the **fallback**, and it shrinks by one entry every time a
 * cipher gains a core — that is the phased rollout, visible in the type
 * system. It is deliberately NOT a general-purpose block-size table: a cipher
 * listed here can't run a mode of operation and can't take padding, so its
 * block width is only ever needed for this one answer ("exactly one block").
 * The moment a cipher has a core, `paddingLimits` reads `core.blockByteLength`
 * instead and this entry goes away.
 *
 * Keeping the size here rather than in a parallel `BLOCK_BYTES_BY_CIPHER`
 * record is intentional: a second table next to `SUPPORTED_CIPHER_MODES_BY_CIPHER`
 * would be one more thing to drift, and it would claim to be authoritative
 * about block sizes while the cores are the real source of truth.
 */
const singleBlockLimits = (cipher: Cipher): { min: number; max: number } => {
  switch (cipher) {
    case "speck-32-64-be":
    case "speck-32-64-le":
      return { min: 4, max: 4 };
    case "serpent-128":
    case "serpent-192":
    case "serpent-256":
      return { min: 16, max: 16 };
    case "des":
      return { min: 8, max: 8 };
    case "twofish":
      return { min: 16, max: 16 };
    // AES and Blowfish always have a core, so they never reach here. The arms
    // exist to keep the switch exhaustive over `Cipher` — which is what makes a
    // NEW cipher that lacks a core a compile error rather than a runtime throw.
    // This is the rollout shrinking one entry at a time, visible in the type
    // system: Blowfish moved up here when its core landed in Phase C.
    case "aes-128":
    case "aes-192":
    case "aes-256":
      return { min: 16, max: 16 };
    case "blowfish":
      return { min: 8, max: 8 };
    default: {
      const _exhaustive: never = cipher;
      throw new Error(`paddingLimits: unhandled cipher: ${_exhaustive as string}`);
    }
  }
};

/**
 * Allowed raw input byte-length range for (mode, scheme, cipher, cipherMode).
 * Used by the Run handler to give a friendly error when the user's input is
 * the wrong size.
 *
 * Three families of behavior, keyed off whether the cipher has a
 * `BlockCipherCore` — the same fact that decides whether it can run a mode at
 * all:
 *
 *   • **No core** (Speck/Serpent/DES/Twofish today): one fixed-size block,
 *     regardless of mode or padding choice. The padding selector is disabled
 *     in the UI.
 *
 *   • **Core, single-block**: exactly one block on decrypt; on encrypt,
 *     0..B-1 / 1..B / B..B depending on the padding scheme.
 *
 *   • **Core, multi-block (ECB/CBC)**: N × B bytes, up to MAX_BLOCKS_UI
 *     blocks. PKCS#7 / zero-pad / iso7816-4 each accept short input on
 *     encrypt (their pad step expands to the next block boundary); decrypt
 *     needs a clean block multiple.
 *
 *   • **Core, CTR** (designed for, not built): no padding, any length up to
 *     the cap — the keystream truncates to the original length.
 *
 * Every bound is derived from the core's block width `B` rather than a
 * hardcoded 16 — and since Blowfish's core landed (Phase C), the app itself
 * exercises that: a Blowfish PKCS#7 encrypt bounds at 0..7, not 0..15.
 */
export const paddingLimits = (
  mode: "encrypt" | "decrypt",
  scheme: PaddingScheme,
  cipher: Cipher,
  cipherMode: CipherMode = "single-block",
): { min: number; max: number } => {
  const core = blockCipherCoreFor(cipher);
  if (core === undefined) return singleBlockLimits(cipher);

  const B = core.blockByteLength;
  const MAX_BYTES = MAX_BLOCKS_UI * B;

  // ── Multi-block (ECB / CBC) ─────────────────────────────────────────────
  if (cipherMode === "ecb" || cipherMode === "cbc") {
    if (mode === "decrypt") {
      // Decrypt input must be a clean ciphertext block multiple. The Run
      // handler also checks the alignment; this just bounds the overall
      // range. min=B because we need at least one block to act on.
      return { min: B, max: MAX_BYTES };
    }
    // Encrypt: every padding scheme produces a clean multi-block output;
    // the pad step itself enforces its scheme-specific invariants on
    // shorter inputs. The UI just caps the overall length.
    switch (scheme) {
      case "none":
        // No pad to fill the last block, so the input must already be a
        // whole multiple. The Run handler checks alignment; we bound the range.
        return { min: B, max: MAX_BYTES };
      case "pkcs7":
      case "iso7816-4":
        // Always-adds-≥1-byte schemes: encrypting `MAX_BYTES` bytes would
        // append a full extra padding block, going past the UI cap. So top
        // out at MAX_BYTES - 1 so the padded result stays ≤ MAX_BYTES.
        return { min: 0, max: MAX_BYTES - 1 };
      case "zero-pad":
        // Zero-pad is the one scheme that doesn't always add a byte: an input
        // already a multiple of B produces no extra padding, so it can use the
        // full range — except length 0, which would yield no blocks to iterate.
        return { min: 1, max: MAX_BYTES };
    }
  }

  // ── CTR (designed for, not built — see `docs/plans/foamy-prancing-wren.md`) ──
  // CTR doesn't use the padding overlay (no padding needed; the keystream
  // is truncated to plaintext length). The byte-length range is purely the
  // UI cap. Same on encrypt and decrypt (CTR is symmetric).
  if (cipherMode === "ctr") {
    return { min: 0, max: MAX_BYTES };
  }

  // ── Single-block ───────────────────────────────────────────────────────
  if (mode === "decrypt") return { min: B, max: B };
  switch (scheme) {
    case "none":
      return { min: B, max: B };
    case "pkcs7":
      return { min: 0, max: B - 1 };
    case "zero-pad":
      return { min: 1, max: B };
    case "iso7816-4":
      return { min: 0, max: B - 1 };
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
