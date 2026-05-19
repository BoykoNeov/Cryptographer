/**
 * Provenance registry wire-up. Importing this module side-effects every
 * provenance fn into `REGISTRY` via `registerProvenance` — once. The App
 * imports this file alongside the simulator registry; consumers
 * (MatrixView, RoundKeyPanel) call `lookupProvenance` to dispatch.
 *
 * Pattern mirrors `src/ciphers/default-registry.ts` for the core step
 * registry: a single side-effecting init function, called eagerly.
 * Idempotent: re-importing in tests after `__resetProvenanceForTests`
 * re-runs initialization cleanly.
 *
 * Coverage at v1 (cross-checked by `tests/provenance-registry-contract.test.ts`):
 *   - AES: SubBytes, ShiftRows, MixColumns, AddRoundKey
 *   - Serpent: AddRoundKey, SubBytes
 * Remaining shipped matrix4x4 / bytes step types live on the
 * `PROVENANCE_NO_OP_ALLOWLIST` in `registry.ts` with explicit reasons.
 */

import {
  aesAddRoundKeyProvenance,
  aesMixColumnsProvenance,
  aesShiftRowsProvenance,
  aesSubBytesProvenance,
} from "./aes";
import {
  desExpandRProvenance,
  desFinalPermutationProvenance,
  desInitialPermutationProvenance,
  desPPermutationProvenance,
  desSBoxesProvenance,
  desXorWithKProvenance,
} from "./des";
import { __resetProvenanceForTests, registerProvenance } from "./registry";
import { serpentAddRoundKeyProvenance, serpentSubBytesProvenance } from "./serpent";

let initialized = false;

/**
 * Idempotent initialization. Skip on second call so module-import order
 * (or test files re-importing after `__resetProvenanceForTests`) doesn't
 * trip the duplicate-registration throw inside `registerProvenance`.
 */
export const initProvenanceRegistry = (): void => {
  if (initialized) return;
  registerProvenance("generic.byte-substitution@1", aesSubBytesProvenance);
  registerProvenance("generic.shift-rows@1", aesShiftRowsProvenance);
  registerProvenance("generic.mix-columns@1", aesMixColumnsProvenance);
  registerProvenance("generic.add-round-key@1", aesAddRoundKeyProvenance);
  registerProvenance("serpent.add-round-key@1", serpentAddRoundKeyProvenance);
  registerProvenance("serpent.sub-bytes@1", serpentSubBytesProvenance);
  // Phase 4 of `docs/plans/des-feistel.md` — six DES step types. Output
  // byte → contributing input-byte set, computed from the FIPS table
  // (for IP/FP/E/P) or the static S-box layout (for s-boxes).
  registerProvenance("des.initial-permutation@1", desInitialPermutationProvenance);
  registerProvenance("des.final-permutation@1", desFinalPermutationProvenance);
  registerProvenance("des.expand-R@1", desExpandRProvenance);
  registerProvenance("des.xor-with-K@1", desXorWithKProvenance);
  registerProvenance("des.s-boxes@1", desSBoxesProvenance);
  registerProvenance("des.p-permutation@1", desPPermutationProvenance);
  initialized = true;
};

// Side-effect: eager init at module load. App.tsx imports this file
// once at startup; subsequent imports are no-ops thanks to the guard.
initProvenanceRegistry();

// Re-export the lookup + allowlist so consumers only need one import.
export { lookupProvenance, PROVENANCE_NO_OP_ALLOWLIST, hasProvenanceFn } from "./registry";
export type { ProvenanceFn, ProvenanceSource } from "./registry";

/**
 * Test-only: reset the registry AND clear the `initialized` flag so a
 * subsequent `initProvenanceRegistry()` repopulates from scratch. Tests
 * that want a fresh contract-test environment call this in `beforeEach`.
 */
export const __resetProvenanceRegistryForTests = (): void => {
  __resetProvenanceForTests();
  initialized = false;
};
