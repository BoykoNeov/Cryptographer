/**
 * Default registry: pairs every step type referenced by the built-in
 * cipher specs with its executor and (educational) documentation.
 *
 * Adding a new cipher: import its step types from src/steps/<name>.ts and
 * register them here with their docs. The UI will pick them up
 * automatically — no UI changes needed for new step types unless their
 * params can't be edited by the existing ParamEditor blocks.
 */

import { liftLegacyExecutor } from "../core/port-projection";
import { StepRegistry } from "../core/registry";
import { addRoundKey, addRoundKeyDoc } from "../steps/add-round-key";
import { auxCopy, auxCopyDoc, auxCopyMeta, auxCopyPortContract } from "../steps/aux-copy";
import { auxLoad, auxLoadDoc, auxLoadMeta, auxLoadPortContract } from "../steps/aux-load";
import { auxXor, auxXorDoc, auxXorMeta, auxXorPortContract } from "../steps/aux-xor";
import { byteSubstitution, byteSubstitutionDoc } from "../steps/byte-substitution";
import { computeBlockCount, computeBlockCountDoc } from "../steps/compute-block-count";
import { concatBlocks, concatBlocksDoc } from "../steps/concat-blocks";
import { desExpandR, desExpandRDoc } from "../steps/des-expand-r";
import { desFinalPermutation, desFinalPermutationDoc } from "../steps/des-final-permutation";
import { desInitialPermutation, desInitialPermutationDoc } from "../steps/des-initial-permutation";
import { desKeySchedule, desKeyScheduleDoc } from "../steps/des-key-schedule";
import { desPPermutation, desPPermutationDoc } from "../steps/des-p-permutation";
import { desSBoxes, desSBoxesDoc } from "../steps/des-s-boxes";
import { desXorWithK, desXorWithKDoc } from "../steps/des-xor-with-k";
import { feistelToyAddK, feistelToyAddKDoc } from "../steps/feistel-toy-add-k";
import { iso78164Pad, iso78164PadDoc } from "../steps/iso7816-4-pad";
import { iso78164Unpad, iso78164UnpadDoc } from "../steps/iso7816-4-unpad";
import { ivLoad, ivLoadDoc, ivLoadMeta, ivLoadPortContract } from "../steps/iv-load";
import {
  keyExpansion,
  keyExpansionDoc,
  keyExpansionV2,
  keyExpansionV2Doc,
} from "../steps/key-expansion";
import { loadBlock, loadBlockDoc } from "../steps/load-block";
import { mixColumns, mixColumnsDoc } from "../steps/mix-columns";
import { pkcs7Pad, pkcs7PadDoc } from "../steps/pkcs7-pad";
import { pkcs7Unpad, pkcs7UnpadDoc } from "../steps/pkcs7-unpad";
import { serpentAddRoundKey, serpentAddRoundKeyDoc } from "../steps/serpent-add-round-key";
import { serpentBitPermutation, serpentBitPermutationDoc } from "../steps/serpent-bit-permutation";
import {
  serpentInvLinearTransform,
  serpentInvLinearTransformDoc,
} from "../steps/serpent-inv-linear-transform";
import { serpentKeyExpansion, serpentKeyExpansionDoc } from "../steps/serpent-key-expansion";
import {
  serpentLinearTransform,
  serpentLinearTransformDoc,
} from "../steps/serpent-linear-transform";
import { serpentSubBytes, serpentSubBytesDoc } from "../steps/serpent-sub-bytes";
import { shiftRows, shiftRowsDoc } from "../steps/shift-rows";
import { speckKeySchedule, speckKeyScheduleDoc } from "../steps/speck-key-schedule";
import { speckRound, speckRoundDoc } from "../steps/speck-round";
import { speckRoundInverse, speckRoundInverseDoc } from "../steps/speck-round-inverse";
import { splitBlocks, splitBlocksDoc } from "../steps/split-blocks";
import { stateToAux, stateToAuxDoc } from "../steps/state-to-aux";
import { storeBlock, storeBlockDoc } from "../steps/store-block";
import { xorAuxIntoState, xorAuxIntoStateDoc } from "../steps/xor-aux-into-state";
import { zeroPad, zeroPadDoc } from "../steps/zero-pad";
import { zeroUnpad, zeroUnpadDoc } from "../steps/zero-unpad";

export const buildDefaultRegistry = (): StepRegistry => {
  const r = new StepRegistry();
  r.register("generic.byte-substitution@1", {
    executor: byteSubstitution,
    doc: byteSubstitutionDoc,
  });
  r.register("generic.shift-rows@1", { executor: shiftRows, doc: shiftRowsDoc });
  r.register("generic.mix-columns@1", { executor: mixColumns, doc: mixColumnsDoc });
  r.register("generic.add-round-key@1", { executor: addRoundKey, doc: addRoundKeyDoc });
  r.register("aes.key-expansion@1", { executor: keyExpansion, doc: keyExpansionDoc });
  // @2: relaxed `rounds === Nk + 6` assertion + on-the-fly Rcon extension.
  // Drives the duplicate-round feature; canonical specs stay on @1 and the
  // mutator rewrites the type to @2 when bumping rounds past the standard
  // count. ParamEditor renders both versions through the same block.
  r.register("aes.key-expansion@2", { executor: keyExpansionV2, doc: keyExpansionV2Doc });
  // ─── Padding chain (Phase: plaintext input + visible padding) ──────────
  // BytesState ↔ MatrixState boundary steps plus three pad/unpad pairs.
  // Each pair is generic over `blockSize` so they drop into future block
  // ciphers (DES/3DES, Twofish, Serpent) by parameter, not by code change.
  //
  // Three schemes are registered so the UI can A/B their behavior in the
  // trace: PKCS#7 (RFC 5652), zero-pad (ISO/IEC 9797-1 method 1, lossy),
  // and ISO 7816-4 (sentinel-marked). Each pair's `doc.detail` calls out
  // the trade-offs vs. the others so the educational story is captured.
  r.register("generic.pkcs7-pad@1", { executor: pkcs7Pad, doc: pkcs7PadDoc });
  r.register("generic.pkcs7-unpad@1", { executor: pkcs7Unpad, doc: pkcs7UnpadDoc });
  r.register("generic.zero-pad@1", { executor: zeroPad, doc: zeroPadDoc });
  r.register("generic.zero-unpad@1", { executor: zeroUnpad, doc: zeroUnpadDoc });
  r.register("generic.iso7816-4-pad@1", { executor: iso78164Pad, doc: iso78164PadDoc });
  r.register("generic.iso7816-4-unpad@1", { executor: iso78164Unpad, doc: iso78164UnpadDoc });
  r.register("generic.load-block@1", { executor: loadBlock, doc: loadBlockDoc });
  r.register("generic.store-block@1", { executor: storeBlock, doc: storeBlockDoc });
  // ─── Multi-block iteration boundary (Phase: ECB/CBC/CTR modes) ─────────
  // split-blocks turns a padded BytesState into MatrixState[] for the
  // `iterate` runtime; concat-blocks reverses that after the loop;
  // compute-block-count writes the iteration count to aux. All three
  // are AES-shaped today (blockSize=16) — see each step's doc for the
  // generalization story when a non-matrix block cipher arrives.
  r.register("generic.split-blocks@1", { executor: splitBlocks, doc: splitBlocksDoc });
  r.register("generic.concat-blocks@1", { executor: concatBlocks, doc: concatBlocksDoc });
  r.register("generic.compute-block-count@1", {
    executor: computeBlockCount,
    doc: computeBlockCountDoc,
  });
  // ─── Aux operation primitives (Slice 10 of the 2D editor plan) ─────────
  // Three small steps that let a user *compose* block-cipher chaining
  // modes (CBC, OFB, CFB) inside the visual editor instead of choosing
  // from a fixed list. Each is graceful when its read keys are missing —
  // the runtime records the miss in `TraceFrame.auxReadMissing` and the
  // graph view's validateGraph (Slice 9) surfaces an orphaned-read
  // warning glyph on the node. That keeps half-wired specs debuggable
  // during palette-driven authoring instead of throwing mid-spec.
  //
  // **Slice 1.2 (universal port-dataflow Phase 1)** — these three step
  // types plus `generic.iv-load@1` below are the FIRST registrations to
  // use the `kind: "ported"` variant. Each declares colocated
  // `ProjectionMetadata` + `PortContract` (per Decision C — metadata
  // lives next to the executor that owns it, not in a central side-map).
  // The runtime branches on `portedDispatchEnabled`: when on, runs the
  // ported execution path through `liftLegacyExecutor`'s wrapping; when
  // off, the `legacy` field provides the legacy-shape executor for the
  // unchanged dispatch. Frame-parity is gated by
  // `tests/runtime-ported-dispatch-aux-only.test.ts`.
  r.register("generic.aux-load@1", {
    kind: "ported",
    executor: liftLegacyExecutor(auxLoad, auxLoadMeta),
    legacy: auxLoad,
    shape: auxLoadPortContract,
    meta: auxLoadMeta,
    doc: auxLoadDoc,
  });
  r.register("generic.aux-xor@1", {
    kind: "ported",
    executor: liftLegacyExecutor(auxXor, auxXorMeta),
    legacy: auxXor,
    shape: auxXorPortContract,
    meta: auxXorMeta,
    doc: auxXorDoc,
  });
  r.register("generic.aux-copy@1", {
    kind: "ported",
    executor: liftLegacyExecutor(auxCopy, auxCopyMeta),
    legacy: auxCopy,
    shape: auxCopyPortContract,
    meta: auxCopyMeta,
    doc: auxCopyDoc,
  });
  // ─── Chaining-mode primitives (Phase 2 of multi-block AES — CBC) ───────
  // Three step types that compose into a CBC body inside the iterate
  // loop, and generalize to OFB/CFB without rewrites:
  //   • iv-load: Uint8Array aux → MatrixState aux (one-shot, pre-loop).
  //   • xor-aux-into-state: state ⊕= aux[name]; the chaining XOR.
  //   • state-to-aux: clone state into aux[name]; the chain snapshot.
  // The post-AES decrypt chain-advance (chain := next-chain) reuses the
  // existing `generic.aux-copy@1` — no fourth primitive needed. See
  // `aes-cbc-builder.ts` for how they assemble.
  //
  // `iv-load` lifts in Slice 1.2 (universal port-dataflow); its output
  // port carries layout `"matrix-cm-4x4"` so the runtime reconstructs
  // the MatrixState that downstream `xor-aux-into-state` expects.
  r.register("generic.iv-load@1", {
    kind: "ported",
    executor: liftLegacyExecutor(ivLoad, ivLoadMeta),
    legacy: ivLoad,
    shape: ivLoadPortContract,
    meta: ivLoadMeta,
    doc: ivLoadDoc,
  });
  r.register("generic.xor-aux-into-state@1", {
    executor: xorAuxIntoState,
    doc: xorAuxIntoStateDoc,
  });
  r.register("generic.state-to-aux@1", { executor: stateToAux, doc: stateToAuxDoc });
  // ─── Speck (ARX block cipher, second cipher family) ────────────────────
  // Three step types complete a full Speck cipher: a key-schedule that
  // expands an m-word master key into `rounds` round-key words, a forward
  // ARX round, and its inverse. Speck32/64 ships as two cipher specs in
  // the UI (BE-paper and LE-NSA byte orders), but the step code is one
  // copy parametric on `byteOrder`. The conventions compute the same
  // word-level cipher; only byte serialization at the boundary differs.
  r.register("speck.key-schedule@1", { executor: speckKeySchedule, doc: speckKeyScheduleDoc });
  r.register("speck.round@1", { executor: speckRound, doc: speckRoundDoc });
  r.register("speck.round-inverse@1", { executor: speckRoundInverse, doc: speckRoundInverseDoc });
  // ─── Serpent (AES-finalist SP-network, third cipher family) ────────────
  // Six step types: key expansion, a single bit-permutation step used as
  // both IP and FP (table-driven), AddRoundKey, a bitsliced 4-bit SubBytes
  // (used for both forward and inverse — S-box table is the per-leaf param),
  // and forward + inverse Linear Transform. All three Serpent variants
  // (128/192/256) share the registered types; only the key length and the
  // key-expansion `keyByteLength` param differ across them.
  r.register("serpent.key-expansion@1", {
    executor: serpentKeyExpansion,
    doc: serpentKeyExpansionDoc,
  });
  r.register("serpent.bit-permutation@1", {
    executor: serpentBitPermutation,
    doc: serpentBitPermutationDoc,
  });
  r.register("serpent.add-round-key@1", {
    executor: serpentAddRoundKey,
    doc: serpentAddRoundKeyDoc,
  });
  r.register("serpent.sub-bytes@1", { executor: serpentSubBytes, doc: serpentSubBytesDoc });
  r.register("serpent.linear-transform@1", {
    executor: serpentLinearTransform,
    doc: serpentLinearTransformDoc,
  });
  r.register("serpent.inv-linear-transform@1", {
    executor: serpentInvLinearTransform,
    doc: serpentInvLinearTransformDoc,
  });
  // ─── Toy Feistel F (Phase 2 of the DES + branching primitive plan) ─────
  // Test-fixture step type exercising the branching primitive end-to-end
  // without DES's complexity. Asymmetric F = (R + k) mod 256 per byte;
  // see `src/steps/feistel-toy-add-k.ts` for why addition (not XOR) is
  // chosen. NOT in the cipher selector — referenced only by Phase 2 tests.
  r.register("feistel.toy-add-k@1", { executor: feistelToyAddK, doc: feistelToyAddKDoc });
  // ─── DES (Phase 3 of the DES + branching primitive plan) ───────────────
  // The first cipher to use the `feistel-round` branching primitive. Seven
  // step types implement the FIPS 46-3 algorithm: a key schedule that
  // expands a 64-bit master key into 16 × 48-bit round keys, IP / FP at
  // the cipher boundary, and four step types composing the F function
  // (E-expand → XOR with K_i → 8 parallel S-boxes → P-permute) inside the
  // R track of each Feistel round.
  //
  // All bit permutations use FIPS bit numbering (1-indexed, MSB-first) via
  // helpers in `src/steps/des-bit-ops.ts` — distinct from Serpent's LSB-
  // first convention to match the standard's tables verbatim.
  //
  // The DES spec is registered in `defaults` (Phase 3) but not yet exposed
  // in the cipher selector (Phase 4). Saved documents stay at schema v1
  // since users can't currently reach a DES Save through the UI.
  r.register("des.key-schedule@1", { executor: desKeySchedule, doc: desKeyScheduleDoc });
  r.register("des.initial-permutation@1", {
    executor: desInitialPermutation,
    doc: desInitialPermutationDoc,
  });
  r.register("des.final-permutation@1", {
    executor: desFinalPermutation,
    doc: desFinalPermutationDoc,
  });
  r.register("des.expand-R@1", { executor: desExpandR, doc: desExpandRDoc });
  r.register("des.xor-with-K@1", { executor: desXorWithK, doc: desXorWithKDoc });
  r.register("des.s-boxes@1", { executor: desSBoxes, doc: desSBoxesDoc });
  r.register("des.p-permutation@1", { executor: desPPermutation, doc: desPPermutationDoc });
  return r;
};
