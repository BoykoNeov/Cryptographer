/**
 * Narration registry wire-up. Importing this module side-effects every
 * narration fn into `REGISTRY` via `registerNarration` — once. The App
 * imports this file alongside the provenance and simulator registries;
 * the `<StepNarration />` component calls `lookupNarration` to dispatch.
 *
 * Pattern mirrors `src/ui/provenance/index.ts`. Idempotent: re-importing
 * after `__resetNarrationForTests` re-runs initialization cleanly.
 *
 * Coverage after Phase 3 (cross-checked by
 * `tests/narration-registry-contract.test.ts`):
 *   - AES round body (Phase 1): SubBytes, ShiftRows, MixColumns, AddRoundKey
 *   - Serpent byte-level + bit-permutation (Phase 2): SubBytes, AddRoundKey,
 *     Bit-Permutation (IP / FP)
 *   - Speck (Phase 2): Round (forward), Round-inverse
 *   - Padding (Phase 3): pkcs7 pad/unpad, zero pad/unpad, iso7816-4 pad/unpad
 *   - Boundary (Phase 3): load-block, store-block, split-blocks,
 *     concat-blocks, compute-block-count
 *   - Aux (Phase 3): aux-load, aux-xor, aux-copy, iv-load,
 *     xor-aux-into-state, state-to-aux
 * Allowlist shrinks to the irreducible 6 entries (4 key-expansion +
 * 2 bit-level Serpent linear transforms).
 */

import {
  aesAddRoundKeyNarration,
  aesMixColumnsNarration,
  aesShiftRowsNarration,
  aesSubBytesNarration,
} from "./aes";
import {
  auxCopyNarration,
  auxLoadNarration,
  auxXorNarration,
  ivLoadNarration,
  stateToAuxNarration,
  xorAuxIntoStateNarration,
} from "./aux-primitives";
import {
  computeBlockCountNarration,
  concatBlocksNarration,
  loadBlockNarration,
  splitBlocksNarration,
  storeBlockNarration,
} from "./boundary";
import {
  iso78164PadNarration,
  iso78164UnpadNarration,
  pkcs7PadNarration,
  pkcs7UnpadNarration,
  zeroPadNarration,
  zeroUnpadNarration,
} from "./padding";
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
  // Phase 3 — padding + boundary + aux primitives.
  registerNarration("generic.pkcs7-pad@1", pkcs7PadNarration);
  registerNarration("generic.pkcs7-unpad@1", pkcs7UnpadNarration);
  registerNarration("generic.zero-pad@1", zeroPadNarration);
  registerNarration("generic.zero-unpad@1", zeroUnpadNarration);
  registerNarration("generic.iso7816-4-pad@1", iso78164PadNarration);
  registerNarration("generic.iso7816-4-unpad@1", iso78164UnpadNarration);
  registerNarration("generic.load-block@1", loadBlockNarration);
  registerNarration("generic.store-block@1", storeBlockNarration);
  registerNarration("generic.split-blocks@1", splitBlocksNarration);
  registerNarration("generic.concat-blocks@1", concatBlocksNarration);
  registerNarration("generic.compute-block-count@1", computeBlockCountNarration);
  registerNarration("generic.aux-load@1", auxLoadNarration);
  registerNarration("generic.aux-xor@1", auxXorNarration);
  registerNarration("generic.aux-copy@1", auxCopyNarration);
  registerNarration("generic.iv-load@1", ivLoadNarration);
  registerNarration("generic.xor-aux-into-state@1", xorAuxIntoStateNarration);
  registerNarration("generic.state-to-aux@1", stateToAuxNarration);
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
