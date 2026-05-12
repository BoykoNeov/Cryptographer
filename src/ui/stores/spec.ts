/**
 * Spec store. Holds the currently-displayed CipherSpec plus the UI
 * dimensions that select among the available canonical specs:
 *   • mode        — "encrypt" | "decrypt"
 *   • cipher      — "aes-128" | "aes-192" | "aes-256" | "speck-*"  (stores/cipher.ts)
 *   • cipherMode  — "single-block" | "ecb" | "cbc" | "ctr"          (stores/cipher-mode.ts)
 *
 * Together they pick from `defaults[cipher][cipherMode][mode]`. The padding
 * store is a fourth, orthogonal preference layered on TOP of the chosen
 * spec via `applyPaddingScheme`.
 *
 * Edits go through this module so the UI never builds new specs by hand —
 * all mutations route through src/core/spec-mutations.ts, which guarantees
 * the readonly tree is rebuilt correctly and reference equality holds on
 * untouched branches (cheaper Solid re-renders).
 *
 * Non-AES ciphers (Speck32/64) only support "single-block" today. The
 * defaults table records this with a partial inner record, and
 * `resolveDefault` falls back to single-block if a requested mode is
 * missing for the active cipher. That fallback lets the user pick "ECB"
 * for AES-128, then flip cipher to Speck without crashing — they just
 * land back in single-block on the Speck side.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { aes128EcbSpec } from "@/ciphers/aes-128-ecb";
import { aes128EcbDecryptSpec } from "@/ciphers/aes-128-ecb-decrypt";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes192DecryptSpec } from "@/ciphers/aes-192-decrypt";
import { aes256Spec } from "@/ciphers/aes-256";
import { aes256DecryptSpec } from "@/ciphers/aes-256-decrypt";
import { speck32_64BeSpec } from "@/ciphers/speck-32-64-be";
import { speck32_64BeDecryptSpec } from "@/ciphers/speck-32-64-be-decrypt";
import { speck32_64LeSpec } from "@/ciphers/speck-32-64-le";
import { speck32_64LeDecryptSpec } from "@/ciphers/speck-32-64-le-decrypt";
import {
  type PaddingScheme,
  applyPaddingScheme,
  updateAllStepsByType,
  updateStepParams,
} from "@/core/spec-mutations";
import type { CipherSpec, Json } from "@/core/types";
import { createSignal } from "solid-js";
import { type Cipher, setCipher as setCipherSignal, useCipher } from "./cipher";
import {
  type CipherMode,
  isCipherModeSupported,
  setCipherMode as setCipherModeSignal,
  useCipherMode,
} from "./cipher-mode";
import { setPaddingScheme, usePaddingScheme } from "./padding";

// ─── Mode ────────────────────────────────────────────────────────────────

export type Mode = "encrypt" | "decrypt";

// 3D table of canonical specs: defaults[cipher][cipherMode][mode]. The
// inner per-cipherMode record is partial — Speck only supports
// single-block today; AES-128 ships single-block + ecb in Phase 1, with
// cbc/ctr arriving in later phases.
const defaults: Record<Cipher, Partial<Record<CipherMode, Record<Mode, CipherSpec>>>> = {
  "aes-128": {
    "single-block": { encrypt: aes128Spec, decrypt: aes128DecryptSpec },
    ecb: { encrypt: aes128EcbSpec, decrypt: aes128EcbDecryptSpec },
  },
  "aes-192": {
    "single-block": { encrypt: aes192Spec, decrypt: aes192DecryptSpec },
  },
  "aes-256": {
    "single-block": { encrypt: aes256Spec, decrypt: aes256DecryptSpec },
  },
  "speck-32-64-be": {
    "single-block": { encrypt: speck32_64BeSpec, decrypt: speck32_64BeDecryptSpec },
  },
  "speck-32-64-le": {
    "single-block": { encrypt: speck32_64LeSpec, decrypt: speck32_64LeDecryptSpec },
  },
};

/**
 * Pick the right canonical spec for the active (cipher, cipherMode, mode)
 * triple, falling back to single-block when the requested cipherMode isn't
 * registered for the cipher. The fallback keeps the UI from crashing when
 * the user switches cipher to one that doesn't support the active mode
 * (e.g. AES-128/ECB → Speck/ECB).
 */
const resolveDefault = (cipher: Cipher, cipherMode: CipherMode, mode: Mode): CipherSpec => {
  const byMode = defaults[cipher];
  const forCipherMode = byMode[cipherMode] ?? byMode["single-block"];
  if (!forCipherMode) {
    throw new Error(`No spec registered for cipher=${cipher}`);
  }
  return forCipherMode[mode];
};

// ─── Signals ─────────────────────────────────────────────────────────────

const [mode, setModeSignal] = createSignal<Mode>("encrypt");
// Seed initial spec with the persisted (cipher, cipherMode, padding).
const [spec, setSpec] = createSignal<CipherSpec>(
  applyPaddingScheme(
    resolveDefault(useCipher()(), useCipherMode()(), "encrypt"),
    "encrypt",
    usePaddingScheme()(),
  ),
);

export const useMode = () => mode;
export const useSpec = () => spec;

// ─── Mutators ────────────────────────────────────────────────────────────

/**
 * Switch between encrypt and decrypt. RESETS the spec to the default for
 * the new (cipher, cipherMode, mode) — any in-progress experiments are
 * discarded. The active padding scheme is re-applied to the freshly-
 * loaded canonical spec so the user's choice persists across the flip.
 */
export const setMode = (m: Mode): void => {
  setModeSignal(m);
  setSpec(
    applyPaddingScheme(
      resolveDefault(useCipher()(), useCipherMode()(), m),
      m,
      usePaddingScheme()(),
    ),
  );
};

/**
 * Switch the active cipher. Replaces the spec with the new cipher's
 * canonical default for the current (cipherMode, mode), then re-applies
 * the active padding overlay. If the new cipher doesn't support the
 * current cipherMode, the cipherMode signal is RESET to "single-block"
 * before the spec is rebuilt. Without this reset, `resolveDefault` would
 * silently fall back to single-block but the dropdown would still show
 * the unsupported mode — `paddingLimits` would then return the
 * multi-block range, the spec would run as single-block with the
 * padding overlay, and the user would see a deep "load-block: expected
 * 16, got 32" error instead of any UI signal.
 */
export const setCipher = (c: Cipher): void => {
  setCipherSignal(c);
  if (!isCipherModeSupported(c, useCipherMode()())) {
    setCipherModeSignal("single-block");
  }
  setSpec(
    applyPaddingScheme(resolveDefault(c, useCipherMode()(), mode()), mode(), usePaddingScheme()()),
  );
};

/**
 * Switch the block-cipher mode of operation (single-block / ecb / cbc /
 * ctr). Replaces the spec with the multi-block factory's output for the
 * current cipher + mode, then re-applies the padding overlay. If the
 * requested cipherMode isn't registered for the current cipher, falls
 * back to single-block.
 */
export const setCipherMode = (m: CipherMode): void => {
  setCipherModeSignal(m);
  setSpec(
    applyPaddingScheme(resolveDefault(useCipher()(), m, mode()), mode(), usePaddingScheme()()),
  );
};

/**
 * Switch the padding scheme. Persists the choice and rebuilds the current
 * spec with the new overlay. User edits to canonical AES leaves survive
 * because `applyPaddingScheme` only touches the overlay step types; it
 * walks the existing spec to strip+rebuild the padding chain without
 * disturbing the AES rounds.
 */
export const setPadding = (scheme: PaddingScheme): void => {
  setPaddingScheme(scheme);
  setSpec((s) => applyPaddingScheme(s, mode(), scheme));
};

/**
 * Edit one specific step's params. The UI uses this when the user changes
 * a value in the ParamEditor and wants the change scoped to a single step.
 */
export const editStepParams = (stepId: string, params: Json): void => {
  setSpec((s) => updateStepParams(s, stepId, params));
};

/**
 * Apply an update to every step of a given type. Used for "swap the S-box
 * across all 10 round SubBytes steps in one click" — the more dramatic
 * modularity demo, since AES the cipher conceptually has ONE S-box.
 */
export const editAllStepsByType = (stepType: string, update: (params: Json) => Json): void => {
  setSpec((s) => updateAllStepsByType(s, stepType, update));
};

/**
 * Restore the default spec for the current (cipher, cipherMode, mode).
 * Preserves the padding scheme + cipher + cipherMode.
 */
export const resetSpec = (): void => {
  setSpec(
    applyPaddingScheme(
      resolveDefault(useCipher()(), useCipherMode()(), mode()),
      mode(),
      usePaddingScheme()(),
    ),
  );
};

/** Test-only reset; production code uses the setters above. */
export const __resetSpecForTests = (): void => {
  setModeSignal("encrypt");
  setSpec(applyPaddingScheme(aes128Spec, "encrypt", usePaddingScheme()()));
};
