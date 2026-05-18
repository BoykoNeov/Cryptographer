/**
 * Narration registry wire-up. Importing this module side-effects every
 * narration fn into `REGISTRY` via `registerNarration` — once. The App
 * imports this file alongside the provenance and simulator registries;
 * the `<StepNarration />` component calls `lookupNarration` to dispatch.
 *
 * Pattern mirrors `src/ui/provenance/index.ts`. Idempotent: re-importing
 * after `__resetNarrationForTests` re-runs initialization cleanly.
 *
 * Coverage after Phase 2 (cross-checked by
 * `tests/narration-registry-contract.test.ts`):
 *   - AES round body: SubBytes, ShiftRows, MixColumns, AddRoundKey
 *   - Serpent byte-level + bit-permutation: SubBytes, AddRoundKey,
 *     Bit-Permutation (IP / FP)
 *   - Speck: Round (forward), Round-inverse
 * Phase 3 adds padding + boundary + aux primitives. Remaining shipped
 * matrix / bytes step types live on `NARRATION_NO_OP_ALLOWLIST` with
 * reasons (key-expansion + the 2 bit-level Serpent linear transforms).
 */

import {
  aesAddRoundKeyNarration,
  aesMixColumnsNarration,
  aesShiftRowsNarration,
  aesSubBytesNarration,
} from "./aes";
import { __resetNarrationForTests, registerNarration } from "./registry";
import {
  serpentAddRoundKeyNarration,
  serpentBitPermutationNarration,
  serpentSubBytesNarration,
} from "./serpent";
import { speckRoundInverseNarration, speckRoundNarration } from "./speck";

let initialized = false;

/**
 * Idempotent initialization. Skip on second call so module-import order
 * (or test files re-importing after `__resetNarrationForTests`) doesn't
 * trip the duplicate-registration throw inside `registerNarration`.
 */
export const initNarrationRegistry = (): void => {
  if (initialized) return;
  // Phase 1 — AES round body.
  registerNarration("generic.byte-substitution@1", aesSubBytesNarration);
  registerNarration("generic.shift-rows@1", aesShiftRowsNarration);
  registerNarration("generic.mix-columns@1", aesMixColumnsNarration);
  registerNarration("generic.add-round-key@1", aesAddRoundKeyNarration);
  // Phase 2 — Serpent byte-level + bit-permutation, Speck rounds.
  registerNarration("serpent.sub-bytes@1", serpentSubBytesNarration);
  registerNarration("serpent.add-round-key@1", serpentAddRoundKeyNarration);
  registerNarration("serpent.bit-permutation@1", serpentBitPermutationNarration);
  registerNarration("speck.round@1", speckRoundNarration);
  registerNarration("speck.round-inverse@1", speckRoundInverseNarration);
  initialized = true;
};

// Side-effect: eager init at module load. App.tsx imports this file
// once at startup; subsequent imports are no-ops thanks to the guard.
initNarrationRegistry();

// Re-export the lookup + allowlist so consumers only need one import.
export {
  hasNarrationFn,
  lookupNarration,
  NARRATION_NO_OP_ALLOWLIST,
} from "./registry";
export type { NarrationFn, NarrationUnit } from "./registry";

/**
 * Test-only: reset the registry AND clear the `initialized` flag so a
 * subsequent `initNarrationRegistry()` repopulates from scratch.
 */
export const __resetNarrationRegistryForTests = (): void => {
  __resetNarrationForTests();
  initialized = false;
};
