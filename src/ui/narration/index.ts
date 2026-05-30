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

import { auxCopyNarration, auxLoadNarration, auxXorNarration } from "./aux-primitives";
import { coerceNarration } from "./coerce";
import { rejoinNarration } from "./combine-kinds";
import {
  desExpandRNarration,
  desFinalPermutationNarration,
  desInitialPermutationNarration,
  desPPermutationNarration,
  desSBoxesNarration,
  desXorWithKNarration,
} from "./des";
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
  // The Phase-1 matrix AES round-body narrators (byte-substitution /
  // shift-rows / mix-columns / add-round-key) were retired in Phase 5
  // Slice 5.1 (2026-05-30) with their step types + the MatrixState shape.
  // The shipped port-native AES primitives narrate via PortFlowView + the
  // per-leaf `narrationOverride`, not a registered cell-narrator.
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
  // The matrix boundary + chaining narrators (load-block / store-block /
  // split-blocks / concat-blocks / compute-block-count / iv-load /
  // xor-aux-into-state / state-to-aux) were retired in Phase 5 Slice 5.1
  // (2026-05-30) with their step types + the MatrixState shape. The
  // user-composable byte-typed aux primitives stay.
  registerNarration("generic.aux-load@1", auxLoadNarration);
  registerNarration("generic.aux-xor@1", auxXorNarration);
  registerNarration("generic.aux-copy@1", auxCopyNarration);
  // Phase 4 of `docs/plans/des-feistel.md` — DES step types use the bit-
  // level structural-overview + per-output-byte drill pattern (IP/FP/E/P);
  // S-boxes get per-S-box units; xor-with-K is cell-wise XOR. The rejoin
  // synthetic stepType `__rejoin__` carries combine-kind-specific prose.
  registerNarration("des.initial-permutation@1", desInitialPermutationNarration);
  registerNarration("des.final-permutation@1", desFinalPermutationNarration);
  registerNarration("des.expand-R@1", desExpandRNarration);
  registerNarration("des.xor-with-K@1", desXorWithKNarration);
  registerNarration("des.s-boxes@1", desSBoxesNarration);
  registerNarration("des.p-permutation@1", desPPermutationNarration);
  registerNarration("__rejoin__", rejoinNarration);
  // Slice 1.12 of universal-port-dataflow plan — synthetic `__coerce__`
  // frames are runtime-synthesized when a ported-dispatch input port's
  // declared byteLength doesn't match the source byte count. Coercion
  // is flag-on-only and no shipped spec triggers it, but the narrator
  // ships so a future palette-dropped novice spec with mismatched ports
  // gets learner-friendly prose rather than a naked default frame view.
  registerNarration("__coerce__", coerceNarration);
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
