/**
 * Spec store. Holds the currently-displayed CipherSpec plus a "mode" flag
 * that distinguishes encrypt vs. decrypt (and in the future, other ciphers).
 *
 * Edits go through this module so the UI never builds new specs by hand —
 * all mutations route through src/core/spec-mutations.ts, which guarantees
 * the readonly tree is rebuilt correctly and reference equality holds on
 * untouched branches (cheaper Solid re-renders).
 *
 * The padding overlay is composed in here too: setMode / resetSpec /
 * setPadding all funnel through `applyPaddingScheme` so the active scheme
 * is preserved across mode flips and respected on fresh loads.
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import {
  type PaddingScheme,
  applyPaddingScheme,
  updateAllStepsByType,
  updateStepParams,
} from "@/core/spec-mutations";
import type { CipherSpec, Json } from "@/core/types";
import { createSignal } from "solid-js";
import { setPaddingScheme, usePaddingScheme } from "./padding";

// ─── Mode ────────────────────────────────────────────────────────────────
// Add new entries here as new ciphers/specs are introduced. The keys are
// what the cipher-mode dropdown shows; values are the default specs.

export type Mode = "encrypt" | "decrypt";

const defaultsByMode: Record<Mode, CipherSpec> = {
  encrypt: aes128Spec,
  decrypt: aes128DecryptSpec,
};

// ─── Signals ─────────────────────────────────────────────────────────────

const [mode, setModeSignal] = createSignal<Mode>("encrypt");
// Seed initial spec with the persisted padding scheme — if the user reloads
// with padding="pkcs7", they should land back in PKCS#7 with the pad/load
// chain already in place, not in canonical mode.
const [spec, setSpec] = createSignal<CipherSpec>(
  applyPaddingScheme(aes128Spec, "encrypt", usePaddingScheme()()),
);

export const useMode = () => mode;
export const useSpec = () => spec;

// ─── Mutators ────────────────────────────────────────────────────────────

/**
 * Switch between encrypt and decrypt. This RESETS the spec to the default
 * for the new mode — any in-progress experiments on the previous spec are
 * discarded. That's intentional: the two modes have different step trees,
 * so carrying edits across is meaningless. The active padding scheme is
 * re-applied to the freshly-loaded canonical spec so the user's choice
 * persists across the flip.
 */
export const setMode = (m: Mode): void => {
  setModeSignal(m);
  setSpec(applyPaddingScheme(defaultsByMode[m], m, usePaddingScheme()()));
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
 * Restore the default spec for the current mode. Used by the "Reset" button
 * after the user has experimented and wants to compare against canonical
 * AES, or just clear out a broken state. Preserves the padding scheme.
 */
export const resetSpec = (): void => {
  setSpec(applyPaddingScheme(defaultsByMode[mode()], mode(), usePaddingScheme()()));
};

/** Test-only reset; production code uses `setMode`+`setPadding`. */
export const __resetSpecForTests = (): void => {
  setModeSignal("encrypt");
  setSpec(applyPaddingScheme(aes128Spec, "encrypt", usePaddingScheme()()));
};
