/**
 * Spec store. Holds the currently-displayed CipherSpec plus a "mode" flag
 * that distinguishes encrypt vs. decrypt (and in the future, other ciphers).
 *
 * Edits go through this module so the UI never builds new specs by hand —
 * all mutations route through src/core/spec-mutations.ts, which guarantees
 * the readonly tree is rebuilt correctly and reference equality holds on
 * untouched branches (cheaper Solid re-renders).
 */

import { aes128Spec } from "@/ciphers/aes-128";
import { aes128DecryptSpec } from "@/ciphers/aes-128-decrypt";
import { updateAllStepsByType, updateStepParams } from "@/core/spec-mutations";
import type { CipherSpec, Json } from "@/core/types";
import { createSignal } from "solid-js";

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
const [spec, setSpec] = createSignal<CipherSpec>(aes128Spec);

export const useMode = () => mode;
export const useSpec = () => spec;

// ─── Mutators ────────────────────────────────────────────────────────────

/**
 * Switch between encrypt and decrypt. This RESETS the spec to the default
 * for the new mode — any in-progress experiments on the previous spec are
 * discarded. That's intentional: the two modes have different step trees,
 * so carrying edits across is meaningless.
 */
export const setMode = (m: Mode): void => {
  setModeSignal(m);
  setSpec(defaultsByMode[m]);
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
 * AES, or just clear out a broken state.
 */
export const resetSpec = (): void => {
  setSpec(defaultsByMode[mode()]);
};
