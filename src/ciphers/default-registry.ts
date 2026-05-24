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
import {
  addRoundKey,
  addRoundKeyDoc,
  addRoundKeyMeta,
  addRoundKeyPortContract,
} from "../steps/add-round-key";
import { auxCopy, auxCopyDoc, auxCopyMeta, auxCopyPortContract } from "../steps/aux-copy";
import { auxLoad, auxLoadDoc, auxLoadMeta, auxLoadPortContract } from "../steps/aux-load";
import { auxXor, auxXorDoc, auxXorMeta, auxXorPortContract } from "../steps/aux-xor";
import {
  byteSubstitution,
  byteSubstitutionDoc,
  byteSubstitutionMeta,
  byteSubstitutionPortContract,
} from "../steps/byte-substitution";
import { computeBlockCount, computeBlockCountDoc } from "../steps/compute-block-count";
import {
  concatBlocks,
  concatBlocksDoc,
  concatBlocksMeta,
  concatBlocksPortContract,
} from "../steps/concat-blocks";
import {
  desExpandR,
  desExpandRDoc,
  desExpandRMeta,
  desExpandRPortContract,
} from "../steps/des-expand-r";
import {
  desFinalPermutation,
  desFinalPermutationDoc,
  desFinalPermutationMeta,
  desFinalPermutationPortContract,
} from "../steps/des-final-permutation";
import {
  desInitialPermutation,
  desInitialPermutationDoc,
  desInitialPermutationMeta,
  desInitialPermutationPortContract,
} from "../steps/des-initial-permutation";
import {
  desKeySchedule,
  desKeyScheduleDoc,
  desKeyScheduleMeta,
  desKeySchedulePortContract,
} from "../steps/des-key-schedule";
import {
  desPPermutation,
  desPPermutationDoc,
  desPPermutationMeta,
  desPPermutationPortContract,
} from "../steps/des-p-permutation";
import {
  desSBoxes,
  desSBoxesDoc,
  desSBoxesMeta,
  desSBoxesPortContract,
} from "../steps/des-s-boxes";
import {
  desXorWithK,
  desXorWithKDoc,
  desXorWithKMeta,
  desXorWithKPortContract,
} from "../steps/des-xor-with-k";
import {
  feistelToyAddK,
  feistelToyAddKDoc,
  feistelToyAddKMeta,
  feistelToyAddKPortContract,
} from "../steps/feistel-toy-add-k";
import {
  iso78164Pad,
  iso78164PadDoc,
  iso78164PadMeta,
  iso78164PadPortContract,
} from "../steps/iso7816-4-pad";
import {
  iso78164Unpad,
  iso78164UnpadDoc,
  iso78164UnpadMeta,
  iso78164UnpadPortContract,
} from "../steps/iso7816-4-unpad";
import { ivLoad, ivLoadDoc, ivLoadMeta, ivLoadPortContract } from "../steps/iv-load";
import {
  keyExpansion,
  keyExpansionDoc,
  keyExpansionMeta,
  keyExpansionPortContract,
  keyExpansionV2,
  keyExpansionV2Doc,
  keyExpansionV2Meta,
  keyExpansionV2PortContract,
} from "../steps/key-expansion";
import { loadBlock, loadBlockDoc } from "../steps/load-block";
import {
  mixColumns,
  mixColumnsDoc,
  mixColumnsMeta,
  mixColumnsPortContract,
} from "../steps/mix-columns";
import { pkcs7Pad, pkcs7PadDoc, pkcs7PadMeta, pkcs7PadPortContract } from "../steps/pkcs7-pad";
import {
  pkcs7Unpad,
  pkcs7UnpadDoc,
  pkcs7UnpadMeta,
  pkcs7UnpadPortContract,
} from "../steps/pkcs7-unpad";
import {
  serpentAddRoundKey,
  serpentAddRoundKeyDoc,
  serpentAddRoundKeyMeta,
  serpentAddRoundKeyPortContract,
} from "../steps/serpent-add-round-key";
import {
  serpentBitPermutation,
  serpentBitPermutationDoc,
  serpentBitPermutationMeta,
  serpentBitPermutationPortContract,
} from "../steps/serpent-bit-permutation";
import {
  serpentInvLinearTransform,
  serpentInvLinearTransformDoc,
  serpentInvLinearTransformMeta,
  serpentInvLinearTransformPortContract,
} from "../steps/serpent-inv-linear-transform";
import {
  serpentKeyExpansion,
  serpentKeyExpansionDoc,
  serpentKeyExpansionMeta,
  serpentKeyExpansionPortContract,
} from "../steps/serpent-key-expansion";
import {
  serpentLinearTransform,
  serpentLinearTransformDoc,
  serpentLinearTransformMeta,
  serpentLinearTransformPortContract,
} from "../steps/serpent-linear-transform";
import {
  serpentSubBytes,
  serpentSubBytesDoc,
  serpentSubBytesMeta,
  serpentSubBytesPortContract,
} from "../steps/serpent-sub-bytes";
import { shiftRows, shiftRowsDoc, shiftRowsMeta, shiftRowsPortContract } from "../steps/shift-rows";
import {
  speckKeySchedule,
  speckKeyScheduleDoc,
  speckKeyScheduleMeta,
  speckKeySchedulePortContract,
} from "../steps/speck-key-schedule";
import {
  speckRound,
  speckRoundDoc,
  speckRoundMeta,
  speckRoundPortContract,
} from "../steps/speck-round";
import {
  speckRoundInverse,
  speckRoundInverseDoc,
  speckRoundInverseMeta,
  speckRoundInversePortContract,
} from "../steps/speck-round-inverse";
import {
  splitBlocks,
  splitBlocksDoc,
  splitBlocksMeta,
  splitBlocksPortContract,
} from "../steps/split-blocks";
import {
  stateToAux,
  stateToAuxDoc,
  stateToAuxMeta,
  stateToAuxPortContract,
} from "../steps/state-to-aux";
import { storeBlock, storeBlockDoc } from "../steps/store-block";
import {
  xorAuxIntoState,
  xorAuxIntoStateDoc,
  xorAuxIntoStateMeta,
  xorAuxIntoStatePortContract,
} from "../steps/xor-aux-into-state";
import { zeroPad, zeroPadDoc, zeroPadMeta, zeroPadPortContract } from "../steps/zero-pad";
import { zeroUnpad, zeroUnpadDoc, zeroUnpadMeta, zeroUnpadPortContract } from "../steps/zero-unpad";

export const buildDefaultRegistry = (): StepRegistry => {
  const r = new StepRegistry();
  // ─── AES core step types (Slice 1.4 — universal port-dataflow) ─────────
  // All six AES step types lift in Slice 1.4. byte-substitution + add-
  // round-key were the original Phase-0 side-map targets; Slice 1.4
  // moved them (plus the four other AES step types below) to colocated
  // metadata per Decision C, and Slice 1.9 deleted the side-map outright
  // per Decision A. shift-rows + mix-columns are pure state-only — same
  // shape as byte-substitution. Key-expansion is the FIRST one-to-many
  // writer in the universal-port migration — port-per-roundkey per
  // Decision B, with `outputs(params)` in function form sized by
  // `params.rounds` (the user-picked Slice 1.4 contract evolution).
  r.register("generic.byte-substitution@1", {
    kind: "ported",
    executor: liftLegacyExecutor(byteSubstitution, byteSubstitutionMeta),
    legacy: byteSubstitution,
    shape: byteSubstitutionPortContract,
    meta: byteSubstitutionMeta,
    doc: byteSubstitutionDoc,
  });
  r.register("generic.shift-rows@1", {
    kind: "ported",
    executor: liftLegacyExecutor(shiftRows, shiftRowsMeta),
    legacy: shiftRows,
    shape: shiftRowsPortContract,
    meta: shiftRowsMeta,
    doc: shiftRowsDoc,
  });
  r.register("generic.mix-columns@1", {
    kind: "ported",
    executor: liftLegacyExecutor(mixColumns, mixColumnsMeta),
    legacy: mixColumns,
    shape: mixColumnsPortContract,
    meta: mixColumnsMeta,
    doc: mixColumnsDoc,
  });
  r.register("generic.add-round-key@1", {
    kind: "ported",
    executor: liftLegacyExecutor(addRoundKey, addRoundKeyMeta),
    legacy: addRoundKey,
    shape: addRoundKeyPortContract,
    meta: addRoundKeyMeta,
    doc: addRoundKeyDoc,
  });
  r.register("aes.key-expansion@1", {
    kind: "ported",
    executor: liftLegacyExecutor(keyExpansion, keyExpansionMeta),
    legacy: keyExpansion,
    shape: keyExpansionPortContract,
    meta: keyExpansionMeta,
    doc: keyExpansionDoc,
  });
  // @2: relaxed `rounds === Nk + 6` assertion + on-the-fly Rcon extension.
  // Drives the duplicate-round feature; canonical specs stay on @1 and the
  // mutator rewrites the type to @2 when bumping rounds past the standard
  // count. ParamEditor renders both versions through the same block.
  // Shares the @1 meta + contract verbatim (identical param shape).
  r.register("aes.key-expansion@2", {
    kind: "ported",
    executor: liftLegacyExecutor(keyExpansionV2, keyExpansionV2Meta),
    legacy: keyExpansionV2,
    shape: keyExpansionV2PortContract,
    meta: keyExpansionV2Meta,
    doc: keyExpansionV2Doc,
  });
  // ─── Padding chain (Phase: plaintext input + visible padding) ──────────
  // BytesState ↔ MatrixState boundary steps plus three pad/unpad pairs.
  // Each pair is generic over `blockSize` so they drop into future block
  // ciphers (DES/3DES, Twofish, Serpent) by parameter, not by code change.
  //
  // Three schemes are registered so the UI can A/B their behavior in the
  // trace: PKCS#7 (RFC 5652), zero-pad (ISO/IEC 9797-1 method 1, lossy),
  // and ISO 7816-4 (sentinel-marked). Each pair's `doc.detail` calls out
  // the trade-offs vs. the others so the educational story is captured.
  // **Slice 1.3 (universal port-dataflow Phase 1)** — six padding step
  // types lift as `kind: "ported"`. All bytes→bytes, no aux. The
  // matching pair `load-block` / `store-block` stay legacy this slice:
  // they are shape-transforming (bytes ↔ matrix4x4-bytes) and the
  // current `ProjectionMetadata.stateLayout` single-field cannot describe
  // a shape-transforming step. **Slice 2.0b-ii (Phase 2, 2026-05-24)**:
  // `split-blocks` + `concat-blocks` are lifted (registered below as
  // `kind: "ported"`) using the new `"matrix-cm-4x4-array"` aux-layout
  // tag for `MatrixState[]` and the option-C `stateToBytes` relaxation
  // (any non-bigint state variant decodes when expected is `"bytes"`).
  // `compute-block-count` stays legacy — its `number` aux value still
  // has no port-projection encoding rule. `load-block`/`store-block`
  // still wait for asymmetric stateInput/stateOutput layout meta.
  r.register("generic.pkcs7-pad@1", {
    kind: "ported",
    executor: liftLegacyExecutor(pkcs7Pad, pkcs7PadMeta),
    legacy: pkcs7Pad,
    shape: pkcs7PadPortContract,
    meta: pkcs7PadMeta,
    doc: pkcs7PadDoc,
  });
  r.register("generic.pkcs7-unpad@1", {
    kind: "ported",
    executor: liftLegacyExecutor(pkcs7Unpad, pkcs7UnpadMeta),
    legacy: pkcs7Unpad,
    shape: pkcs7UnpadPortContract,
    meta: pkcs7UnpadMeta,
    doc: pkcs7UnpadDoc,
  });
  r.register("generic.zero-pad@1", {
    kind: "ported",
    executor: liftLegacyExecutor(zeroPad, zeroPadMeta),
    legacy: zeroPad,
    shape: zeroPadPortContract,
    meta: zeroPadMeta,
    doc: zeroPadDoc,
  });
  r.register("generic.zero-unpad@1", {
    kind: "ported",
    executor: liftLegacyExecutor(zeroUnpad, zeroUnpadMeta),
    legacy: zeroUnpad,
    shape: zeroUnpadPortContract,
    meta: zeroUnpadMeta,
    doc: zeroUnpadDoc,
  });
  r.register("generic.iso7816-4-pad@1", {
    kind: "ported",
    executor: liftLegacyExecutor(iso78164Pad, iso78164PadMeta),
    legacy: iso78164Pad,
    shape: iso78164PadPortContract,
    meta: iso78164PadMeta,
    doc: iso78164PadDoc,
  });
  r.register("generic.iso7816-4-unpad@1", {
    kind: "ported",
    executor: liftLegacyExecutor(iso78164Unpad, iso78164UnpadMeta),
    legacy: iso78164Unpad,
    shape: iso78164UnpadPortContract,
    meta: iso78164UnpadMeta,
    doc: iso78164UnpadDoc,
  });
  r.register("generic.load-block@1", { executor: loadBlock, doc: loadBlockDoc });
  r.register("generic.store-block@1", { executor: storeBlock, doc: storeBlockDoc });
  // ─── Multi-block iteration boundary (Phase: ECB/CBC/CTR modes) ─────────
  // split-blocks turns a padded BytesState into MatrixState[] for the
  // `iterate` runtime; concat-blocks reverses that after the loop;
  // compute-block-count writes the iteration count to aux. All three
  // are AES-shaped today (blockSize=16) — see each step's doc for the
  // generalization story when a non-matrix block cipher arrives.
  r.register("generic.split-blocks@1", {
    kind: "ported",
    executor: liftLegacyExecutor(splitBlocks, splitBlocksMeta),
    legacy: splitBlocks,
    shape: splitBlocksPortContract,
    meta: splitBlocksMeta,
    doc: splitBlocksDoc,
  });
  r.register("generic.concat-blocks@1", {
    kind: "ported",
    executor: liftLegacyExecutor(concatBlocks, concatBlocksMeta),
    legacy: concatBlocks,
    shape: concatBlocksPortContract,
    meta: concatBlocksMeta,
    doc: concatBlocksDoc,
  });
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
  // **Slice 1.5 (universal port-dataflow Phase 1)** — both chaining
  // primitives lift as `kind: "ported"`. `xor-aux-into-state` reads a
  // MatrixState chain (driving Slice 1.5's input-side widening in
  // `runtime.ts:243-261` — the previous hard throw on non-Uint8Array aux
  // becomes a wired path via `auxValueToPortBytes`). `state-to-aux`
  // writes a MatrixState snapshot via the existing output-side
  // `layout: "matrix-cm-4x4"` decode (same path Slice-1.2's `iv-load`
  // already exercises). AES-128 CBC encrypt + decrypt KAT under flag-on
  // is the cipher-level parity gate; per-primitive synthetic specs pin
  // the unit semantics. Frame-parity is gated by
  // `tests/runtime-ported-dispatch-chaining.test.ts`.
  r.register("generic.xor-aux-into-state@1", {
    kind: "ported",
    executor: liftLegacyExecutor(xorAuxIntoState, xorAuxIntoStateMeta),
    legacy: xorAuxIntoState,
    shape: xorAuxIntoStatePortContract,
    meta: xorAuxIntoStateMeta,
    doc: xorAuxIntoStateDoc,
  });
  r.register("generic.state-to-aux@1", {
    kind: "ported",
    executor: liftLegacyExecutor(stateToAux, stateToAuxMeta),
    legacy: stateToAux,
    shape: stateToAuxPortContract,
    meta: stateToAuxMeta,
    doc: stateToAuxDoc,
  });
  // ─── Speck (ARX block cipher, second cipher family) ────────────────────
  // Three step types complete a full Speck cipher: a key-schedule that
  // expands an m-word master key into `rounds` round-key words, a forward
  // ARX round, and its inverse. Speck32/64 ships as two cipher specs in
  // the UI (BE-paper and LE-NSA byte orders), but the step code is one
  // copy parametric on `byteOrder`. The conventions compute the same
  // word-level cipher; only byte serialization at the boundary differs.
  //
  // **Slice 1.6 (universal port-dataflow Phase 1)** — all three Speck
  // step types lift as `kind: "ported"` with colocated metadata per
  // Decision C. Key-schedule is the SECOND one-to-many writer in the
  // migration (after AES key-expansion in Slice 1.4): port-per-roundkey
  // per Decision B, with `outputs(params)` in function form sized by
  // `params.rounds` (22 ports for Speck32/64, vs AES-128's 11). The
  // round + round-inverse step types are state-bearing single-aux-read
  // — same shape as `aes.add-round-key@1`, but `stateLayout: "bytes"`
  // with polymorphic byteLength to cover variant differences (block
  // size = 2 × wordBits / 8 bytes).
  r.register("speck.key-schedule@1", {
    kind: "ported",
    executor: liftLegacyExecutor(speckKeySchedule, speckKeyScheduleMeta),
    legacy: speckKeySchedule,
    shape: speckKeySchedulePortContract,
    meta: speckKeyScheduleMeta,
    doc: speckKeyScheduleDoc,
  });
  r.register("speck.round@1", {
    kind: "ported",
    executor: liftLegacyExecutor(speckRound, speckRoundMeta),
    legacy: speckRound,
    shape: speckRoundPortContract,
    meta: speckRoundMeta,
    doc: speckRoundDoc,
  });
  r.register("speck.round-inverse@1", {
    kind: "ported",
    executor: liftLegacyExecutor(speckRoundInverse, speckRoundInverseMeta),
    legacy: speckRoundInverse,
    shape: speckRoundInversePortContract,
    meta: speckRoundInverseMeta,
    doc: speckRoundInverseDoc,
  });
  // ─── Serpent (AES-finalist SP-network, third cipher family) ────────────
  // Six step types: key expansion, a single bit-permutation step used as
  // both IP and FP (table-driven), AddRoundKey, a bitsliced 4-bit SubBytes
  // (used for both forward and inverse — S-box table is the per-leaf param),
  // and forward + inverse Linear Transform. All three Serpent variants
  // (128/192/256) share the registered types; only the key length and the
  // key-expansion `keyByteLength` param differ across them.
  //
  // **Slice 1.7 (universal port-dataflow Phase 1)** — all six Serpent
  // step types lift as `kind: "ported"` with colocated metadata per
  // Decision C. Key-expansion is the THIRD one-to-many writer in the
  // migration (after AES key-expansion in 1.4 and Speck key-schedule in
  // 1.6): port-per-roundkey per Decision B, with 33 output ports
  // (`key0` … `key32`) — fixed across all three Serpent key sizes,
  // unlike AES (Nr+1 scales with `params.rounds`) and Speck (rounds keys
  // also scale). Function form retained for uniformity with the
  // precedents. AddRoundKey is the same shape as `aes.add-round-key@1`
  // but with `stateLayout: "bytes"` (Serpent state is 16 flat bytes,
  // not a 4×4 matrix). The four pure no-aux steps (bit-permutation,
  // sub-bytes, both LTs) are the cleanest possible lift batch — bytes
  // ↔ bytes 16-byte fixed, no aux traffic, simpler than Slice 1.3's
  // padding primitives (which had variable output lengths).
  //
  // **byteLength: 16 declared on state + aux-read ports**, but absent
  // on key-expansion's output ports — matches the user-picked
  // (2026-05-23) split: state ports follow AES Slice 1.4 posture
  // (honest fixed declaration when no variant exists), key-expansion's
  // round-key output ports follow Slice 1.6 Speck posture (polymorphic
  // for uniformity across the round-key port batch).
  r.register("serpent.key-expansion@1", {
    kind: "ported",
    executor: liftLegacyExecutor(serpentKeyExpansion, serpentKeyExpansionMeta),
    legacy: serpentKeyExpansion,
    shape: serpentKeyExpansionPortContract,
    meta: serpentKeyExpansionMeta,
    doc: serpentKeyExpansionDoc,
  });
  r.register("serpent.bit-permutation@1", {
    kind: "ported",
    executor: liftLegacyExecutor(serpentBitPermutation, serpentBitPermutationMeta),
    legacy: serpentBitPermutation,
    shape: serpentBitPermutationPortContract,
    meta: serpentBitPermutationMeta,
    doc: serpentBitPermutationDoc,
  });
  r.register("serpent.add-round-key@1", {
    kind: "ported",
    executor: liftLegacyExecutor(serpentAddRoundKey, serpentAddRoundKeyMeta),
    legacy: serpentAddRoundKey,
    shape: serpentAddRoundKeyPortContract,
    meta: serpentAddRoundKeyMeta,
    doc: serpentAddRoundKeyDoc,
  });
  r.register("serpent.sub-bytes@1", {
    kind: "ported",
    executor: liftLegacyExecutor(serpentSubBytes, serpentSubBytesMeta),
    legacy: serpentSubBytes,
    shape: serpentSubBytesPortContract,
    meta: serpentSubBytesMeta,
    doc: serpentSubBytesDoc,
  });
  r.register("serpent.linear-transform@1", {
    kind: "ported",
    executor: liftLegacyExecutor(serpentLinearTransform, serpentLinearTransformMeta),
    legacy: serpentLinearTransform,
    shape: serpentLinearTransformPortContract,
    meta: serpentLinearTransformMeta,
    doc: serpentLinearTransformDoc,
  });
  r.register("serpent.inv-linear-transform@1", {
    kind: "ported",
    executor: liftLegacyExecutor(serpentInvLinearTransform, serpentInvLinearTransformMeta),
    legacy: serpentInvLinearTransform,
    shape: serpentInvLinearTransformPortContract,
    meta: serpentInvLinearTransformMeta,
    doc: serpentInvLinearTransformDoc,
  });
  // ─── Toy Feistel F (Phase 2 of the DES + branching primitive plan) ─────
  // Test-fixture step type exercising the branching primitive end-to-end
  // without DES's complexity. Asymmetric F = (R + k) mod 256 per byte;
  // see `src/steps/feistel-toy-add-k.ts` for why addition (not XOR) is
  // chosen. NOT in the cipher selector — referenced only by Phase 2 tests.
  // Lifted to `kind: "ported"` in Slice 1.8 alongside the seven DES steps;
  // byteLength absent on both ports (length-polymorphic per fixture).
  r.register("feistel.toy-add-k@1", {
    kind: "ported",
    executor: liftLegacyExecutor(feistelToyAddK, feistelToyAddKMeta),
    legacy: feistelToyAddK,
    shape: feistelToyAddKPortContract,
    meta: feistelToyAddKMeta,
    doc: feistelToyAddKDoc,
  });
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
  //
  // ─── Slice 1.8 (universal port dataflow) ──────────────────────────────
  // All seven DES step types lifted to `kind: "ported"`. DES is the
  // FOURTH cipher family ported (after AES Slice 1.4, Speck Slice 1.6,
  // Serpent Slice 1.7). Body leaves inside `feistel-round` containers
  // run ported via the same `walk()` recursion that handles iterate-body
  // leaves; the rejoin frame is synthesized by `runFeistelRound` from
  // Uint8Array track outputs — byte-identical between dispatch paths
  // for free, per the parent plan's invariant 2.
  //
  // **byteLength declarations** — fixed honest values everywhere (DES
  // has no variant): IP/FP 8/8, P-permute 4/4, expand-R 4/6 (FIRST
  // asymmetric state-port declaration in the migration), s-boxes 6/4
  // (second asymmetric pair), xor-with-K 6/6 + 6-byte aux read. Round-
  // key output ports on des.key-schedule@1 leave byteLength ABSENT per
  // user pick 2026-05-23 (uniform with Slice 1.6 Speck + Slice 1.7
  // Serpent round-key port batches, even though DES round keys are
  // fixed at 6 bytes). Master-key input port on des.key-schedule@1 IS
  // declared as 8 bytes (DES has no variant — different from AES/Serpent
  // which leave master-key absent for their 16/24/32 byte variants).
  r.register("des.key-schedule@1", {
    kind: "ported",
    executor: liftLegacyExecutor(desKeySchedule, desKeyScheduleMeta),
    legacy: desKeySchedule,
    shape: desKeySchedulePortContract,
    meta: desKeyScheduleMeta,
    doc: desKeyScheduleDoc,
  });
  r.register("des.initial-permutation@1", {
    kind: "ported",
    executor: liftLegacyExecutor(desInitialPermutation, desInitialPermutationMeta),
    legacy: desInitialPermutation,
    shape: desInitialPermutationPortContract,
    meta: desInitialPermutationMeta,
    doc: desInitialPermutationDoc,
  });
  r.register("des.final-permutation@1", {
    kind: "ported",
    executor: liftLegacyExecutor(desFinalPermutation, desFinalPermutationMeta),
    legacy: desFinalPermutation,
    shape: desFinalPermutationPortContract,
    meta: desFinalPermutationMeta,
    doc: desFinalPermutationDoc,
  });
  r.register("des.expand-R@1", {
    kind: "ported",
    executor: liftLegacyExecutor(desExpandR, desExpandRMeta),
    legacy: desExpandR,
    shape: desExpandRPortContract,
    meta: desExpandRMeta,
    doc: desExpandRDoc,
  });
  r.register("des.xor-with-K@1", {
    kind: "ported",
    executor: liftLegacyExecutor(desXorWithK, desXorWithKMeta),
    legacy: desXorWithK,
    shape: desXorWithKPortContract,
    meta: desXorWithKMeta,
    doc: desXorWithKDoc,
  });
  r.register("des.s-boxes@1", {
    kind: "ported",
    executor: liftLegacyExecutor(desSBoxes, desSBoxesMeta),
    legacy: desSBoxes,
    shape: desSBoxesPortContract,
    meta: desSBoxesMeta,
    doc: desSBoxesDoc,
  });
  r.register("des.p-permutation@1", {
    kind: "ported",
    executor: liftLegacyExecutor(desPPermutation, desPPermutationMeta),
    legacy: desPPermutation,
    shape: desPPermutationPortContract,
    meta: desPPermutationMeta,
    doc: desPPermutationDoc,
  });
  return r;
};
