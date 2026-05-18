/**
 * Narration registry wire-up. Importing this module side-effects every
 * narration fn into `REGISTRY` via `registerNarration` — once. The App
 * imports this file alongside the provenance and simulator registries;
 * the `<StepNarration />` component calls `lookupNarration` to dispatch.
 *
 * Pattern mirrors `src/ui/provenance/index.ts`. Idempotent: re-importing
 * after `__resetNarrationForTests` re-runs initialization cleanly.
 *
 * Coverage at Phase 1 (cross-checked by
 * `tests/narration-registry-contract.test.ts`):
 *   - AES round body: SubBytes, ShiftRows, MixColumns, AddRoundKey
 * Phase 2 will add Serpent byte-level + Speck rounds; Phase 3 adds
 * padding + boundary + aux primitives. Remaining shipped matrix /
 * bytes step types live on `NARRATION_NO_OP_ALLOWLIST` with reasons.
 */

import {
  aesAddRoundKeyNarration,
  aesMixColumnsNarration,
  aesShiftRowsNarration,
  aesSubBytesNarration,
} from "./aes";
import { __resetNarrationForTests, registerNarration } from "./registry";

let initialized = false;

/**
 * Idempotent initialization. Skip on second call so module-import order
 * (or test files re-importing after `__resetNarrationForTests`) doesn't
 * trip the duplicate-registration throw inside `registerNarration`.
 */
export const initNarrationRegistry = (): void => {
  if (initialized) return;
  registerNarration("generic.byte-substitution@1", aesSubBytesNarration);
  registerNarration("generic.shift-rows@1", aesShiftRowsNarration);
  registerNarration("generic.mix-columns@1", aesMixColumnsNarration);
  registerNarration("generic.add-round-key@1", aesAddRoundKeyNarration);
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
