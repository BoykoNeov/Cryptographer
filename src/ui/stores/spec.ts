/**
 * Spec store. Holds the currently-displayed CipherSpec plus the two UI
 * dimensions that select among the available canonical specs:
 *   • mode   — "encrypt" | "decrypt"
 *   • cipher — "aes-128" | "aes-192" | "aes-256"   (lives in stores/cipher.ts)
 *
 * Together they index a 3×2 table of canonical specs. The padding store is
 * a third, orthogonal preference layered on TOP of whichever spec was
 * picked.
 *
 * Edits go through this module so the UI never builds new specs by hand —
 * all mutations route through src/core/spec-mutations.ts, which guarantees
 * the readonly tree is rebuilt correctly and reference equality holds on
 * untouched branches (cheaper Solid re-renders).
 *
 * The padding overlay is composed in here too: setMode / setCipher /
 * resetSpec / setPadding all funnel through `applyPaddingScheme` so the
 * active scheme is preserved across mode + cipher flips and respected on
 * fresh loads.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { aes192Spec } from "@/ciphers/aes-192";
import { aes192DecryptSpec } from "@/ciphers/aes-192-decrypt";
import { aes256Spec } from "@/ciphers/aes-256";
import { aes256DecryptSpec } from "@/ciphers/aes-256-decrypt";
import {
  type PaddingScheme,
  applyPaddingScheme,
  updateAllStepsByType,
  updateStepParams,
} from "@/core/spec-mutations";
import type { CipherSpec, Json } from "@/core/types";
import { createSignal } from "solid-js";
import { type Cipher, setCipher as setCipherSignal, useCipher } from "./cipher";
import { setPaddingScheme, usePaddingScheme } from "./padding";

// ─── Mode ────────────────────────────────────────────────────────────────

export type Mode = "encrypt" | "decrypt";

// Two-dimensional table of canonical specs: defaults[cipher][mode]. Adding
// a new cipher (Speck, ChaCha20, ...) means a new row here plus a new entry
// in the cipher-store's `Cipher` union and labels map.
const defaults: Record<Cipher, Record<Mode, CipherSpec>> = {
  "aes-128": { encrypt: aes128Spec, decrypt: aes128DecryptSpec },
  "aes-192": { encrypt: aes192Spec, decrypt: aes192DecryptSpec },
  "aes-256": { encrypt: aes256Spec, decrypt: aes256DecryptSpec },
};

// ─── Signals ─────────────────────────────────────────────────────────────

const [mode, setModeSignal] = createSignal<Mode>("encrypt");
// Seed initial spec with the persisted (cipher, padding) — if the user
// reloads with cipher=AES-256 + padding=PKCS#7, they should land back in
// that configuration with the pad/load chain already in place.
const [spec, setSpec] = createSignal<CipherSpec>(
  applyPaddingScheme(defaults[useCipher()()].encrypt, "encrypt", usePaddingScheme()()),
);

export const useMode = () => mode;
export const useSpec = () => spec;

// ─── Mutators ────────────────────────────────────────────────────────────

/**
 * Switch between encrypt and decrypt. This RESETS the spec to the default
 * for the new (cipher, mode) — any in-progress experiments on the previous
 * spec are discarded. That's intentional: the two modes have different step
 * trees, so carrying edits across is meaningless. The active padding scheme
 * is re-applied to the freshly-loaded canonical spec so the user's choice
 * persists across the flip.
 */
export const setMode = (m: Mode): void => {
  setModeSignal(m);
  setSpec(applyPaddingScheme(defaults[useCipher()()][m], m, usePaddingScheme()()));
};

/**
 * Switch the active cipher (AES-128 / 192 / 256). Replaces the spec with
 * the new cipher's canonical default for the current mode, then re-applies
 * the active padding overlay. Like setMode, any in-progress spec edits are
 * discarded — the new cipher has different round counts and arguably
 * different step ids, so carrying edits across is meaningless.
 *
 * The key field swap (AES-192's 24-byte default → AES-256's 32-byte default)
 * is the App component's responsibility; this store stays focused on the
 * spec tree itself.
 */
export const setCipher = (c: Cipher): void => {
  setCipherSignal(c);
  setSpec(applyPaddingScheme(defaults[c][mode()], mode(), usePaddingScheme()()));
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
 * Restore the default spec for the current (cipher, mode). Used by the
 * "Reset" button after the user has experimented and wants to compare
 * against canonical AES, or just clear out a broken state. Preserves the
 * padding scheme and cipher.
 */
export const resetSpec = (): void => {
  setSpec(applyPaddingScheme(defaults[useCipher()()][mode()], mode(), usePaddingScheme()()));
};

/** Test-only reset; production code uses `setMode`+`setCipher`+`setPadding`. */
export const __resetSpecForTests = (): void => {
  setModeSignal("encrypt");
  setSpec(applyPaddingScheme(aes128Spec, "encrypt", usePaddingScheme()()));
};
