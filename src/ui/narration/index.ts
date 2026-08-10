/**
 * Narration registry wire-up. Importing this module side-effects every
 * narration fn into `REGISTRY` via `registerNarration` — once. The App
 * imports this file alongside the simulator registry; the
 * `<StepNarration />` component calls `lookupNarration` to dispatch.
 *
 * Idempotent: re-importing after `__resetNarrationForTests` re-runs
 * initialization cleanly.
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
 *   - Lattice (2026-08-10): the six Z_q arithmetic steps that are not
 *     element-wise (compress / decompress / cbd / base-case-mul /
 *     byte-encode / byte-decode) plus all five ML-KEM Keccak monoliths.
 *     The three element-wise `zq-vec-*@1` primitives are allowlisted
 *     instead — 256 coefficients per frame, one conceptual unit each.
 *
 * The allowlist is no longer "the irreducible 6" it was at Phase 3; see the
 * per-entry rationales on the constant itself, which are the authority.
 */

import { auxCopyNarration, auxLoadNarration, auxXorNarration } from "./aux-primitives";
import { blowfishKeyScheduleNarration, blowfishSboxLookupNarration } from "./blowfish";
import { coerceNarration } from "./coerce";
import {
  desExpandRNarration,
  desFinalPermutationNarration,
  desInitialPermutationNarration,
  desPPermutationNarration,
  desSBoxesNarration,
  desXorWithKNarration,
} from "./des";
import {
  mlKemHashGNarration,
  mlKemHashHNarration,
  mlKemKdfJNarration,
  mlKemPrfNarration,
  mlKemSampleNttNarration,
  zqBaseCaseMulNarration,
  zqByteDecodeNarration,
  zqByteEncodeNarration,
  zqCbdNarration,
  zqCompressNarration,
  zqDecompressNarration,
} from "./lattice";
import { mt19937SeedNarration, mt19937TwistNarration } from "./mt19937";
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
import { truncateToReferenceNarration } from "./truncate";
import { twofishHExpandNarration, twofishSboxLookupNarration } from "./twofish";

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
  // S-boxes get per-S-box units; xor-with-K is cell-wise XOR. (The Feistel
  // rejoin narrator was retired with the branching primitive in Phase 5
  // Slice 5.3e — port-native DES has no synthetic rejoin frame.)
  registerNarration("des.initial-permutation@1", desInitialPermutationNarration);
  registerNarration("des.final-permutation@1", desFinalPermutationNarration);
  registerNarration("des.expand-R@1", desExpandRNarration);
  registerNarration("des.xor-with-K@1", desXorWithKNarration);
  registerNarration("des.s-boxes@1", desSBoxesNarration);
  registerNarration("des.p-permutation@1", desPPermutationNarration);
  // Slice 1.12 of universal-port-dataflow plan — synthetic `__coerce__`
  // frames are runtime-synthesized when a ported-dispatch input port's
  // declared byteLength doesn't match the source byte count. Coercion
  // is flag-on-only and no shipped spec triggers it, but the narrator
  // ships so a future palette-dropped novice spec with mismatched ports
  // gets learner-friendly prose rather than a naked default frame view.
  registerNarration("__coerce__", coerceNarration);
  // Blowfish (2026-07-11) — value-prose for the two Blowfish-ONLY step types.
  // The F-function S-box lookup (1-byte index → 4-byte key-derived word) and the
  // opaque 521-loop monolith, whose narrator turns it into disclosable pedagogy
  // rows (mix / P-fill / S-fill / result) annotated with the real published
  // P/S values. The round body's shared arithmetic (`xor@1` / `add-mod-32@1` /
  // `xor-with-aux@1` / `concat@1` / `split-bytes@1`) is deliberately left to
  // PortFlowView + each leaf's `narrationOverride` detail — same posture as
  // AES's port-native round body, which carries no value-prose narrator either.
  registerNarration("blowfish.sbox-lookup@1", blowfishSboxLookupNarration);
  registerNarration("blowfish.key-schedule@1", blowfishKeyScheduleNarration);
  // Twofish (2026-07-12) — value-prose for the two Twofish-ONLY step types.
  // The g-function byte→byte S-box lookup and the opaque h-expand monolith,
  // whose narrator turns it into disclosable pedagogy rows (key decode →
  // RS S-vector → S-box construction → h/A-B material) annotated with the real
  // published values. The round body's shared arithmetic (`xor@1` /
  // `add-mod-32@1` / `rotate-bits-right@1` / `concat@1` / `split-bytes@1` /
  // `gf-matrix-multiply@2`) is left to PortFlowView + each leaf's
  // `narrationOverride` — same posture as AES's / Blowfish's port-native round
  // bodies. `twofish.publish-subkeys@1` is an identity passthrough on the
  // allowlist (parity with the four `*.publish-round-keys@1` tails).
  registerNarration("twofish.sbox-lookup@1", twofishSboxLookupNarration);
  registerNarration("twofish.h-expand@1", twofishHExpandNarration);
  // MT19937's two monoliths (2026-08-09). Same reasoning as `h-expand` above,
  // for a stronger version of the same situation: these two are opaque because
  // they are STRUCTURALLY inexpressible as visible loops (one needs the loop
  // index, the other reads three words of the state at once), not because a
  // decomposition would merely be long. A static description alone would ask
  // the learner to take 624 steps on faith, so each gets disclosure rows
  // carrying the REAL words this run produced — read off the frame's own
  // ports, never recomputed. The twelve tempering leaves below them need no
  // narrator: they are ordinary shifts, masks and XORs whose port I/O table is
  // already legible, and they carry per-leaf `narrationOverride` prose.
  registerNarration("mt19937.seed@1", mt19937SeedNarration);
  registerNarration("mt19937.twist@1", mt19937TwistNarration);
  // CTR's ragged tail (2026-07-20) — `truncate-to-reference@1` is a bare-name
  // port-native primitive, so it escapes the contract test's shapeContract
  // scope and could have shipped silently un-narrated. It gets a real narrator
  // anyway because its payload sentence is per-frame value-aware: on the final
  // short block it names the discarded keystream bytes and explains that this
  // is why CTR's ciphertext matches the plaintext length. A static
  // `narrationOverride` cannot branch on the widths, so that sentence — the
  // point of the whole partial-block feature — is only sayable here.
  registerNarration("truncate-to-reference@1", truncateToReferenceNarration);
  // The lattice family (2026-08-10) — every step type introduced by P2 (the
  // lattice arithmetic) and P3 (K-PKE) of the ML-KEM plan, registered ahead of
  // P4 making ML-KEM selectable. Until P4 these render in no user-reachable
  // spec, which is exactly why they could have shipped silently un-narrated:
  // they are bare-name / dotted port-native types with no `shapeContract`, so
  // the contract test's cell-shape walk never saw them. It does now — see the
  // lattice-family block in `tests/narration-registry-contract.test.ts`.
  //
  // Each of these earns a narrator on the `truncate-to-reference@1` criterion —
  // the teaching point is per-frame, so a static `narrationOverride` cannot say
  // it. `ml-kem.sample-ntt@1` is the strongest case in the app: it is the only
  // step whose COST depends on the value, and it publishes the block count on a
  // port so the narrator can report what actually happened. The three
  // `zq-vec-*@1` steps go the other way and sit on NARRATION_NO_OP_ALLOWLIST —
  // 256 coefficients per frame is far past the "don't emit 200 <details>"
  // convention, and the NTT's butterfly leaves already carry per-node
  // `narrationOverride` prose.
  registerNarration("zq-compress@1", zqCompressNarration);
  registerNarration("zq-decompress@1", zqDecompressNarration);
  registerNarration("zq-cbd@1", zqCbdNarration);
  registerNarration("zq-base-case-mul@1", zqBaseCaseMulNarration);
  registerNarration("zq-byte-encode@1", zqByteEncodeNarration);
  registerNarration("zq-byte-decode@1", zqByteDecodeNarration);
  registerNarration("ml-kem.sample-ntt@1", mlKemSampleNttNarration);
  registerNarration("ml-kem.prf@1", mlKemPrfNarration);
  registerNarration("ml-kem.hash-g@1", mlKemHashGNarration);
  registerNarration("ml-kem.hash-h@1", mlKemHashHNarration);
  registerNarration("ml-kem.kdf-j@1", mlKemKdfJNarration);
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
