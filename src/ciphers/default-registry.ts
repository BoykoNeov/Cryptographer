/**
 * Default registry: pairs every step type referenced by the built-in
 * cipher specs with its executor and (educational) documentation.
 *
 * Adding a new cipher: import its step types from src/steps/<name>.ts and
 * register them here with their docs. The UI will pick them up
 * automatically — no UI changes needed for new step types unless their
 * params can't be edited by the existing ParamEditor blocks.
 */

import { StepRegistry } from "../core/registry";
import { addMod16, addMod16Doc, addMod16PortContract } from "../steps/add-mod-16";
import { addMod32, addMod32Doc, addMod32PortContract } from "../steps/add-mod-32";
import { and, andDoc, andPortContract } from "../steps/and";
import {
  appendBe64Length,
  appendBe64LengthDoc,
  appendBe64LengthPortContract,
} from "../steps/append-be64-length";
import { auxCopy, auxCopyDoc, auxCopyMeta, auxCopyPortContract } from "../steps/aux-copy";
import { auxLoad, auxLoadDoc, auxLoadMeta, auxLoadPortContract } from "../steps/aux-load";
import {
  auxLoadBytes,
  auxLoadBytesDoc,
  auxLoadBytesMeta,
  auxLoadBytesPortContract,
} from "../steps/aux-load-bytes";
import { auxXor, auxXorDoc, auxXorMeta, auxXorPortContract } from "../steps/aux-xor";
import {
  blowfishKeySchedule,
  blowfishKeyScheduleDoc,
  blowfishKeyScheduleMeta,
  blowfishKeySchedulePortContract,
} from "../steps/blowfish-key-schedule";
import {
  blowfishSboxLookup,
  blowfishSboxLookupDoc,
  blowfishSboxLookupMeta,
  blowfishSboxLookupPortContract,
} from "../steps/blowfish-sbox-lookup";
import { byteSlice, byteSliceDoc, byteSlicePortContract } from "../steps/byte-slice";
import {
  byteSubstitute,
  byteSubstituteDoc,
  byteSubstitutePortContract,
} from "../steps/byte-substitute";
import {
  bytesToState,
  bytesToStateDoc,
  bytesToStateMeta,
  bytesToStatePortContract,
} from "../steps/bytes-to-state";
import { concat, concatDoc, concatPortContract } from "../steps/concat";
import { condModMul, condModMulDoc, condModMulPortContract } from "../steps/cond-mod-mul";
import { constantLoad, constantLoadDoc, constantLoadPortContract } from "../steps/constant-load";
import {
  desBitPermute,
  desBitPermuteDoc,
  desBitPermutePortContract,
} from "../steps/des-bit-permute";
import { desExpandR, desExpandRDoc, desExpandRPortContract } from "../steps/des-expand-r";
import {
  desFinalPermutation,
  desFinalPermutationDoc,
  desFinalPermutationPortContract,
} from "../steps/des-final-permutation";
import {
  desInitialPermutation,
  desInitialPermutationDoc,
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
  desPPermutationPortContract,
} from "../steps/des-p-permutation";
import {
  desPublishRoundKeys,
  desPublishRoundKeysDoc,
  desPublishRoundKeysMeta,
  desPublishRoundKeysPortContract,
} from "../steps/des-publish-round-keys";
import {
  desRotateHalves,
  desRotateHalvesDoc,
  desRotateHalvesPortContract,
} from "../steps/des-rotate-halves";
import { desSBoxes, desSBoxesDoc, desSBoxesPortContract } from "../steps/des-s-boxes";
import {
  desXorWithK,
  desXorWithKDoc,
  desXorWithKMeta,
  desXorWithKPortContract,
} from "../steps/des-xor-with-k";
import { eeaExtract, eeaExtractDoc, eeaExtractPortContract } from "../steps/eea-extract";
import { eeaStep, eeaStepDoc, eeaStepPortContract } from "../steps/eea-step";
import {
  gfMatrixMultiply,
  gfMatrixMultiplyDoc,
  gfMatrixMultiplyPortContract,
  gfMatrixMultiplyV2,
  gfMatrixMultiplyV2Doc,
  gfMatrixMultiplyV2PortContract,
} from "../steps/gf-matrix-multiply";
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
import {
  keccakIota,
  keccakIotaDoc,
  keccakIotaMeta,
  keccakIotaPortContract,
} from "../steps/keccak-iota";
import { keccakPad, keccakPadDoc, keccakPadPortContract } from "../steps/keccak-pad";
import { keccakTheta, keccakThetaDoc, keccakThetaPortContract } from "../steps/keccak-theta";
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
import { modInverse, modInverseDoc, modInversePortContract } from "../steps/mod-inverse";
import { modMul, modMulDoc, modMulPortContract } from "../steps/mod-mul";
import { mul, mulDoc, mulPortContract } from "../steps/mul";
import { not, notDoc, notPortContract } from "../steps/not";
import { padWithByte, padWithByteDoc, padWithBytePortContract } from "../steps/pad-with-byte";
import { permute, permuteDoc, permutePortContract } from "../steps/permute";
import { pkcs7Pad, pkcs7PadDoc, pkcs7PadMeta, pkcs7PadPortContract } from "../steps/pkcs7-pad";
import {
  pkcs7Unpad,
  pkcs7UnpadDoc,
  pkcs7UnpadMeta,
  pkcs7UnpadPortContract,
} from "../steps/pkcs7-unpad";
import {
  publishKeyParams,
  publishKeyParamsDoc,
  publishKeyParamsMeta,
  publishKeyParamsPortContract,
} from "../steps/publish-key-params";
import {
  publishRoundKeys,
  publishRoundKeysDoc,
  publishRoundKeysMeta,
  publishRoundKeysPortContract,
} from "../steps/publish-round-keys";
import {
  rotateBitsRight,
  rotateBitsRightDoc,
  rotateBitsRightPortContract,
} from "../steps/rotate-bits-right";
import { rotateLanes, rotateLanesDoc, rotateLanesPortContract } from "../steps/rotate-lanes";
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
  serpentKeySbox,
  serpentKeySboxDoc,
  serpentKeySboxPortContract,
} from "../steps/serpent-key-sbox";
import {
  serpentLinearTransform,
  serpentLinearTransformDoc,
  serpentLinearTransformMeta,
  serpentLinearTransformPortContract,
} from "../steps/serpent-linear-transform";
import {
  serpentPublishRoundKeys,
  serpentPublishRoundKeysDoc,
  serpentPublishRoundKeysMeta,
  serpentPublishRoundKeysPortContract,
} from "../steps/serpent-publish-round-keys";
import {
  serpentSubBytes,
  serpentSubBytesDoc,
  serpentSubBytesMeta,
  serpentSubBytesPortContract,
} from "../steps/serpent-sub-bytes";
import {
  shiftBitsRight,
  shiftBitsRightDoc,
  shiftBitsRightPortContract,
} from "../steps/shift-bits-right";
import {
  speckPublishRoundKeys,
  speckPublishRoundKeysDoc,
  speckPublishRoundKeysMeta,
  speckPublishRoundKeysPortContract,
} from "../steps/speck-publish-round-keys";
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
import { splitBytes, splitBytesDoc, splitBytesPortContract } from "../steps/split-bytes";
import {
  stateToBytes,
  stateToBytesDoc,
  stateToBytesMeta,
  stateToBytesPortContract,
} from "../steps/state-to-bytes";
import { sub, subDoc, subPortContract } from "../steps/sub";
import {
  twofishHExpand,
  twofishHExpandDoc,
  twofishHExpandMeta,
  twofishHExpandPortContract,
} from "../steps/twofish-h-expand";
import {
  twofishPublishSubkeys,
  twofishPublishSubkeysDoc,
  twofishPublishSubkeysMeta,
  twofishPublishSubkeysPortContract,
} from "../steps/twofish-publish-subkeys";
import {
  twofishSboxLookup,
  twofishSboxLookupDoc,
  twofishSboxLookupMeta,
  twofishSboxLookupPortContract,
} from "../steps/twofish-sbox-lookup";
import { xor, xorDoc, xorPortContract } from "../steps/xor";
import {
  xorWithAux,
  xorWithAuxDoc,
  xorWithAuxMeta,
  xorWithAuxPortContract,
} from "../steps/xor-with-aux";
import { zeroPad, zeroPadDoc, zeroPadMeta, zeroPadPortContract } from "../steps/zero-pad";
import { zeroUnpad, zeroUnpadDoc, zeroUnpadMeta, zeroUnpadPortContract } from "../steps/zero-unpad";

export const buildDefaultRegistry = (): StepRegistry => {
  const r = new StepRegistry();
  // ─── AES key expansion (port-native since Slice 5.2 — universal-port Phase 5) ───
  // The matrix AES round primitives (generic.byte-substitution@1 /
  // shift-rows@1 / mix-columns@1 / add-round-key@1) were retired in
  // Phase 5 Slice 5.1 (2026-05-30) along with the MatrixState shape — the
  // shipped AES specs run the port-native byte-flat primitives
  // (byte-substitute@1 / permute@1 / gf-matrix-multiply@1 / xor-with-aux@1)
  // registered below. **Slice 5.2 (2026-05-30)** dropped the `legacy:` lift:
  // `keyExpansion` / `keyExpansionV2` are now true `PortedExecutor`s (master
  // key in on the `masterKey` port, round keys out on `key0`…`keyN`). `meta`
  // is RETAINED — the runtime still projects `aux[keyAuxName] → masterKey`
  // and `key${r} → aux[${outputPrefix}.${r}]`, so frames stay byte-identical
  // (only `portInputs`/`portOutputs` newly populate). This monolithic oracle
  // is no longer emitted by any shipped spec — the schedule decomposed into
  // port-native primitives (K1–K4) — so it survives only as KAT oracle /
  // pre-decomposition doc back-compat.
  // It is the one-to-many round-key writer, with `outputs(params)` in
  // function form sized by `params.rounds`.
  r.register("aes.key-expansion@1", {
    kind: "ported",
    executor: keyExpansion,
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
    executor: keyExpansionV2,
    shape: keyExpansionV2PortContract,
    meta: keyExpansionV2Meta,
    doc: keyExpansionV2Doc,
  });
  // Aux-publish tail of the DECOMPOSED key schedule (key-schedule-decomposition
  // plan, Slice K1a). Identity passthrough of the round keys (wired from the
  // repack byte-slices) with `meta.auxWritePorts` mirroring `key${r} →
  // aux[roundKey.${r}]` — byte-identical to what the monolith wrote, so the
  // round-body `xor-with-aux@1` consumers are untouched (B-minimal). This is
  // the one surviving `meta` in the decomposed schedule; the recurrence math
  // above it (`buildAesKeyScheduleNative`) is all pure port-native.
  r.register("aes.publish-round-keys@1", {
    kind: "ported",
    executor: publishRoundKeys,
    shape: publishRoundKeysPortContract,
    meta: publishRoundKeysMeta,
    doc: publishRoundKeysDoc,
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
  // Port-native since Slice 5.2 (2026-05-31): the six padding step types
  // dropped their `legacy:` lift for true `PortedExecutor`s (bytes in/out on
  // the `state` port). `meta` is RETAINED (stateInputPort/stateOutputPort
  // "state"), so the linear inspector reads the `state` port I/O; the
  // frames render in PortFlowView (the honest port view —
  // same rendering SHA-256's `pad`/`length-append` already ship). The
  // intentional throws on malformed padding propagate unchanged.
  r.register("generic.pkcs7-pad@1", {
    kind: "ported",
    executor: pkcs7Pad,
    shape: pkcs7PadPortContract,
    meta: pkcs7PadMeta,
    doc: pkcs7PadDoc,
  });
  r.register("generic.pkcs7-unpad@1", {
    kind: "ported",
    executor: pkcs7Unpad,
    shape: pkcs7UnpadPortContract,
    meta: pkcs7UnpadMeta,
    doc: pkcs7UnpadDoc,
  });
  r.register("generic.zero-pad@1", {
    kind: "ported",
    executor: zeroPad,
    shape: zeroPadPortContract,
    meta: zeroPadMeta,
    doc: zeroPadDoc,
  });
  r.register("generic.zero-unpad@1", {
    kind: "ported",
    executor: zeroUnpad,
    shape: zeroUnpadPortContract,
    meta: zeroUnpadMeta,
    doc: zeroUnpadDoc,
  });
  r.register("generic.iso7816-4-pad@1", {
    kind: "ported",
    executor: iso78164Pad,
    shape: iso78164PadPortContract,
    meta: iso78164PadMeta,
    doc: iso78164PadDoc,
  });
  r.register("generic.iso7816-4-unpad@1", {
    kind: "ported",
    executor: iso78164Unpad,
    shape: iso78164UnpadPortContract,
    meta: iso78164UnpadMeta,
    doc: iso78164UnpadDoc,
  });
  // The matrix multi-block boundary primitives (generic.load-block@1 /
  // store-block@1 / split-blocks@1 / concat-blocks@1 / compute-block-count@1)
  // were retired in Phase 5 Slice 5.1 (2026-05-30) with the MatrixState
  // shape. The shipped ECB/CBC specs run the byte-native `iterate` port
  // mode (seedInput/bodyOutput/chainInput/chainFeedback) instead of the
  // aux-mediated split→iterate→concat machinery these supported.
  // ─── Aux operation primitives (Slice 10 of the 2D editor plan) ─────────
  // Three small steps that let a user *compose* block-cipher chaining
  // modes (CBC, OFB, CFB) inside the visual editor instead of choosing
  // from a fixed list. Each is graceful when its read keys are missing —
  // the runtime records the miss in `TraceFrame.auxReadMissing` and the
  // graph view's validateGraph (Slice 9) surfaces an orphaned-read
  // warning glyph on the node. That keeps half-wired specs debuggable
  // during palette-driven authoring instead of throwing mid-spec.
  //
  // **Port-native since Slice 5.2** (2026-05-31) — these three aux primitives
  // (plus `generic.iv-load@1` below) dropped their `legacy:` lift for true
  // `PortedExecutor`s. `meta` is RETAINED: the runtime projects the aux reads
  // onto named input ports (`from`/`into`/none) and the output ports
  // (`value`/`result`) back to aux (per Decision C — metadata lives next to
  // the executor that owns it). The graceful missing-aux semantics survive —
  // the runtime omits an absent input port AND records the miss in
  // `frame.auxReadMissing` from the same meta bindings, so the Slice 9
  // orphan-read warnings still light up on half-wired specs.
  r.register("generic.aux-load@1", {
    kind: "ported",
    executor: auxLoad,
    shape: auxLoadPortContract,
    meta: auxLoadMeta,
    doc: auxLoadDoc,
  });
  r.register("generic.aux-xor@1", {
    kind: "ported",
    executor: auxXor,
    shape: auxXorPortContract,
    meta: auxXorMeta,
    doc: auxXorDoc,
  });
  r.register("generic.aux-copy@1", {
    kind: "ported",
    executor: auxCopy,
    shape: auxCopyPortContract,
    meta: auxCopyMeta,
    doc: auxCopyDoc,
  });
  // The matrix chaining-mode primitives (generic.iv-load@1 /
  // xor-aux-into-state@1 / state-to-aux@1 / state-to-aux-bytes@1) were
  // retired in Phase 5 Slice 5.1 (2026-05-30) with the MatrixState shape.
  // They produced/consumed MatrixState aux values for the aux-mediated
  // matrix CBC body; the shipped CBC spec now chains in bytes through the
  // `iterate` port mode's `chainInput`/`chainFeedback` (see
  // `aes-cbc-builder.ts`). The user-facing "compose your own mode" palette
  // primitives `generic.aux-load@1` / `aux-xor@1` / `aux-copy@1` above stay
  // (byte-typed; Slice 5.2 converts them to true PortedExecutors).
  // ─── Speck (ARX block cipher, second cipher family) ────────────────────
  // Three step types complete a full Speck cipher: a key-schedule that
  // expands an m-word master key into `rounds` round-key words, a forward
  // ARX round, and its inverse. Speck32/64 ships as two cipher specs in
  // the UI (BE-paper and LE-NSA byte orders), but the step code is one
  // copy parametric on `byteOrder`. The conventions compute the same
  // word-level cipher; only byte serialization at the boundary differs.
  //
  // **Slice 1.6 (universal port-dataflow Phase 1)** lifted all three Speck
  // step types as `kind: "ported"` with colocated metadata per Decision C.
  // **Slice B2 (scaffolding-suppression, 2026-05-30)** then took the two
  // ARX rounds byte-native: their executors are now true `PortedExecutor`s
  // (Uint8Array in/out, no lift adapter, no `legacy` fallback), which flips
  // every shipped Speck spec onto ported dispatch (`requiresPortedDispatch`
  // → true). The metadata is unchanged — the runtime threads the block via
  // `stateInputPort`/`stateOutputPort` and projects `aux[roundKeyAux]` onto
  // the `roundKey` port via `auxReadPorts`, the same projection it ran for
  // the lift adapter.
  //
  // The **monolithic `speck.key-schedule@1` step type is FULLY RETIRED at K2c
  // follow-up (2026-06-01)** — the K2c gate's `AskUserQuestion` picked "retire
  // now" with the option text spelling out executor-registration retirement;
  // the initial K2c closure kept the executor as a KAT oracle for the
  // decomposition test, but an advisor pass flagged the partial-retire as
  // diverging from the user's literal pick. The follow-up commit deletes the
  // step file, drops this registration, and migrates the parity test to an
  // inline Beaulieu 2013 §3 reference implementation. No shipped Speck spec
  // has used this leaf since K2a; the four BE/LE × encrypt/decrypt specs route
  // through the decomposed `key-schedule` group built by
  // `buildSpeck32_64KeyScheduleNative`. Palette-dropping the monolithic leaf
  // is no longer possible; pre-K2 saved Speck docs carrying the leaf will fail
  // to load (acceptable per the "K2a..K2d is a single un-released sub-phase,
  // no tagged release of the K2a state will ever exist" invariant — see
  // `docs/plans/key-schedule-decomposition.md` § K2d back-compat).
  // K2a (2026-06-01): the parallel-name Speck publish tail of the decomposed
  // schedule. Cannot reuse `aes.publish-round-keys@1` — Speck emits `rounds`
  // keys (not `rounds + 1`), and round-key byteLength is polymorphic across
  // Speck variants (not hardcoded 16). One surviving `meta` in the K2
  // decomposition; the recurrence math above it is pure port-native.
  r.register("speck.publish-round-keys@1", {
    kind: "ported",
    executor: speckPublishRoundKeys,
    shape: speckPublishRoundKeysPortContract,
    meta: speckPublishRoundKeysMeta,
    doc: speckPublishRoundKeysDoc,
  });
  r.register("speck.round@1", {
    kind: "ported",
    executor: speckRound,
    shape: speckRoundPortContract,
    meta: speckRoundMeta,
    doc: speckRoundDoc,
  });
  r.register("speck.round-inverse@1", {
    kind: "ported",
    executor: speckRoundInverse,
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
  // Port-native since Slice 5.2 (2026-05-31): dropped the `legacy:` lift,
  // KEEPS `meta` (runtime projects `aux[keyAuxName] → masterKey` and
  // `key${i} → aux[${outputPrefix}.${i}]`, frames byte-identical). Kept only
  // as the KAT oracle + pre-K3 doc back-compat: no shipped spec emits this
  // frame (the schedule decomposed into port-native primitives in K3).
  r.register("serpent.key-expansion@1", {
    kind: "ported",
    executor: serpentKeyExpansion,
    shape: serpentKeyExpansionPortContract,
    meta: serpentKeyExpansionMeta,
    doc: serpentKeyExpansionDoc,
  });
  // K3a (2026-06-02): the decomposed Serpent key schedule's two new leaves.
  // `serpent.key-sbox@1` lifts the monolith's bitsliced-S-box + IP stage (one
  // leaf per round key); `serpent.publish-round-keys@1` is the B-minimal
  // meta-bearing tail that writes `aux["roundKey.0..32"]` byte-identically to
  // the monolith. Cannot reuse `aes.publish-round-keys@1` — Serpent's count is
  // a FIXED 33 (no `rounds` param) and round-key byteLength is polymorphic.
  // `serpent.key-expansion@1` above stays registered as the KAT oracle +
  // back-compat for saved specs; new specs route through
  // `buildSerpentKeyScheduleNative`.
  r.register("serpent.key-sbox@1", {
    kind: "ported",
    executor: serpentKeySbox,
    shape: serpentKeySboxPortContract,
    doc: serpentKeySboxDoc,
  });
  r.register("serpent.publish-round-keys@1", {
    kind: "ported",
    executor: serpentPublishRoundKeys,
    shape: serpentPublishRoundKeysPortContract,
    meta: serpentPublishRoundKeysMeta,
    doc: serpentPublishRoundKeysDoc,
  });
  // ─── Serpent round body — port-native since scaffolding-suppression B3
  //     (2026-05-30). The five round-body executors are true PortedExecutors
  //     (Uint8Array in/out, no `legacy` fallback, no lift adapter); a single
  //     port-native leaf flips `requiresPortedDispatch` true for all six
  //     Serpent specs. `meta` is retained verbatim so the runtime still
  //     projects the threaded state onto each `state` port and (for
  //     add-round-key) `aux[roundKeyAux]` onto the `roundKey` port — exactly
  //     as the lift adapter did, so the flat Serpent specs need ZERO
  //     `portInputs` and the graph topology is unchanged. Mirrors B1 (AES) /
  //     B2 (Speck); `serpent.key-expansion@1` above went port-native in the
  //     cross-cutting key-schedule slice (Slice 5.2, 2026-05-31). ───────────
  r.register("serpent.bit-permutation@1", {
    kind: "ported",
    executor: serpentBitPermutation,
    shape: serpentBitPermutationPortContract,
    meta: serpentBitPermutationMeta,
    doc: serpentBitPermutationDoc,
  });
  r.register("serpent.add-round-key@1", {
    kind: "ported",
    executor: serpentAddRoundKey,
    shape: serpentAddRoundKeyPortContract,
    meta: serpentAddRoundKeyMeta,
    doc: serpentAddRoundKeyDoc,
  });
  r.register("serpent.sub-bytes@1", {
    kind: "ported",
    executor: serpentSubBytes,
    shape: serpentSubBytesPortContract,
    meta: serpentSubBytesMeta,
    doc: serpentSubBytesDoc,
  });
  r.register("serpent.linear-transform@1", {
    kind: "ported",
    executor: serpentLinearTransform,
    shape: serpentLinearTransformPortContract,
    meta: serpentLinearTransformMeta,
    doc: serpentLinearTransformDoc,
  });
  r.register("serpent.inv-linear-transform@1", {
    kind: "ported",
    executor: serpentInvLinearTransform,
    shape: serpentInvLinearTransformPortContract,
    meta: serpentInvLinearTransformMeta,
    doc: serpentInvLinearTransformDoc,
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
  // All seven DES step types are `kind: "ported"`. DES is the FOURTH cipher
  // family ported (after AES Slice 1.4, Speck Slice 1.6, Serpent Slice 1.7).
  // (B4 / Phase 5 5.3e: DES is now built from port-mode `group` rounds wiring
  // `split-bytes`/`des.*`/`xor`/`concat` — no `feistel-round`; the Feistel
  // swap is the concat argument order.)
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
  // Port-native since Slice 5.2 (2026-05-31): dropped the `legacy:` lift,
  // KEEPS `meta` (same hybrid-ported pattern as `aes.key-expansion@1` — the
  // runtime projects `aux[keyAuxName] → masterKey` and `key${r} →
  // aux[${outputPrefix}.${r}]`, frames byte-identical). Kept only as the KAT
  // oracle + pre-K4 doc back-compat: no shipped spec emits this frame (the
  // schedule decomposed into port-native primitives in K4a).
  r.register("des.key-schedule@1", {
    kind: "ported",
    executor: desKeySchedule,
    shape: desKeySchedulePortContract,
    meta: desKeyScheduleMeta,
    doc: desKeyScheduleDoc,
  });
  // ─── B4 (universal-port Phase 4d) — DES round body byte-native ─────────
  // The F-function leaves below dropped `legacy:`/`liftLegacyExecutor` for
  // true `PortedExecutor`s (Uint8Array Map in/out). IP/FP/E/S/P are pure
  // port-native (NO `meta` — bytes flow on the `state` port via the spec's
  // `portInputs`, the Feistel split/recombine expressed as native
  // split-bytes/xor/concat in `des.ts`). `des.xor-with-K@1` stays a hybrid
  // (keeps `meta.auxReadPorts` so the round key projects from
  // `aux[roundKeyAux]` — the `xor-with-aux@1` shape). `des.key-schedule@1`
  // went port-native in Slice 5.2 (hybrid-ported: `legacy:` dropped, `meta`
  // retained — mirrors `aes.key-expansion@1`).
  r.register("des.initial-permutation@1", {
    kind: "ported",
    executor: desInitialPermutation,
    shape: desInitialPermutationPortContract,
    doc: desInitialPermutationDoc,
  });
  r.register("des.final-permutation@1", {
    kind: "ported",
    executor: desFinalPermutation,
    shape: desFinalPermutationPortContract,
    doc: desFinalPermutationDoc,
  });
  r.register("des.expand-R@1", {
    kind: "ported",
    executor: desExpandR,
    shape: desExpandRPortContract,
    doc: desExpandRDoc,
  });
  r.register("des.xor-with-K@1", {
    kind: "ported",
    executor: desXorWithK,
    shape: desXorWithKPortContract,
    meta: desXorWithKMeta,
    doc: desXorWithKDoc,
  });
  r.register("des.s-boxes@1", {
    kind: "ported",
    executor: desSBoxes,
    shape: desSBoxesPortContract,
    doc: desSBoxesDoc,
  });
  r.register("des.p-permutation@1", {
    kind: "ported",
    executor: desPPermutation,
    shape: desPPermutationPortContract,
    doc: desPPermutationDoc,
  });
  // ─── DES key-schedule decomposition (key-schedule-decomposition K4a) ────
  // The decomposed replacement for the monolithic `des.key-schedule@1`. The
  // schedule is pure bit-wiring (no arithmetic): PC-1 → 16× rotate-halves →
  // PC-2. `des.bit-permute@1` (PC-1/PC-2) and `des.rotate-halves@1` are pure
  // port-native (no meta — bytes flow on input/output ports via portInputs).
  // `des.publish-round-keys@1` is the one surviving meta-bearing tail
  // (B-minimal): identity passthrough whose `meta.auxWritePorts` mirrors each
  // round key into `aux["roundKey.0..15"]` byte-identically to the monolith,
  // so the untouched `des.xor-with-K@1` consumers read the same round keys.
  // The monolithic `des.key-schedule@1` stays registered as KAT oracle +
  // back-compat (AES/Serpent precedent — no global rename).
  r.register("des.bit-permute@1", {
    kind: "ported",
    executor: desBitPermute,
    shape: desBitPermutePortContract,
    doc: desBitPermuteDoc,
  });
  r.register("des.rotate-halves@1", {
    kind: "ported",
    executor: desRotateHalves,
    shape: desRotateHalvesPortContract,
    doc: desRotateHalvesDoc,
  });
  r.register("des.publish-round-keys@1", {
    kind: "ported",
    executor: desPublishRoundKeys,
    shape: desPublishRoundKeysPortContract,
    meta: desPublishRoundKeysMeta,
    doc: desPublishRoundKeysDoc,
  });
  // ─── Blowfish (Schneier 1993, fifth cipher family, second Feistel) ─────
  // Two new step types. `blowfish.key-schedule@1` is the ONE deliberately-
  // monolithic step: the 521-self-encryption loop that regenerates the
  // key-dependent P-array + four S-boxes cannot decompose into a legible
  // frame count (unlike AES/Speck/Serpent/DES's bit-plumbing schedules), so
  // it stays opaque and publishes P + S into aux (B-minimal `meta.auxWritePorts`
  // posture, same as `rsa.publish-key-params@1`). The VISIBLE `key ⊕ P` mixing
  // that feeds it is composed from ordinary `xor@1` frames in the spec.
  // `blowfish.sbox-lookup@1` is the F-function's aux-fed 32-bit word lookup —
  // the S-boxes are key-DERIVED (not fixed constants), so the table comes from
  // aux (hybrid `meta.auxReadPorts`, like `xor-with-aux@1`). Everything else in
  // the round body (split/xor/add-mod-32/concat) reuses existing primitives;
  // `L ⊕ P[i]` reuses `xor-with-aux@1`'s parameterizable `auxName`.
  r.register("blowfish.key-schedule@1", {
    kind: "ported",
    executor: blowfishKeySchedule,
    shape: blowfishKeySchedulePortContract,
    meta: blowfishKeyScheduleMeta,
    doc: blowfishKeyScheduleDoc,
  });
  r.register("blowfish.sbox-lookup@1", {
    kind: "ported",
    executor: blowfishSboxLookup,
    shape: blowfishSboxLookupPortContract,
    meta: blowfishSboxLookupMeta,
    doc: blowfishSboxLookupDoc,
  });
  // ─── Twofish (1998 AES finalist, sixth cipher family, third Feistel) ────
  // Three step types. `twofish.h-expand@1` is the OPAQUE half of the key
  // schedule (RS S-vector + key-dependent S-box construction + 40 h evals),
  // publishing A/B intermediates + the four byte→byte S-boxes to aux — but,
  // unlike Blowfish's silent tail, it carries a rich value-prose narrator. The
  // VISIBLE half (the pseudo-Hadamard subkey mixing) is composed from ordinary
  // `add-mod-32@1` / `rotate-bits-right@1` frames, gathered by
  // `twofish.publish-subkeys@1` (the aux-publish tail, allowlisted like the
  // other `*.publish-round-keys@1` tails). `twofish.sbox-lookup@1` is the
  // g-function's aux-fed BYTE→BYTE lookup (Twofish S-boxes are byte→byte, unlike
  // Blowfish's byte→word). The round body's MDS reuses `gf-matrix-multiply@2`
  // (field 0x169); everything else reuses existing port-native primitives.
  r.register("twofish.h-expand@1", {
    kind: "ported",
    executor: twofishHExpand,
    shape: twofishHExpandPortContract,
    meta: twofishHExpandMeta,
    doc: twofishHExpandDoc,
  });
  r.register("twofish.sbox-lookup@1", {
    kind: "ported",
    executor: twofishSboxLookup,
    shape: twofishSboxLookupPortContract,
    meta: twofishSboxLookupMeta,
    doc: twofishSboxLookupDoc,
  });
  r.register("twofish.publish-subkeys@1", {
    kind: "ported",
    executor: twofishPublishSubkeys,
    shape: twofishPublishSubkeysPortContract,
    meta: twofishPublishSubkeysMeta,
    doc: twofishPublishSubkeysDoc,
  });
  // ─── SHA-3 / Keccak (FIPS 202, sponge hash — first non-Merkle–Damgård hash) ─
  // Keccak-f[1600]'s five round steps map to the port-native vocabulary as:
  //   θ → keccak.theta@1 (custom; column parities over non-contiguous lanes)
  //   ρ → rotate-lanes@1 (generic; per-lane LE left-rotate)
  //   π → permute@1       (reused; lane transposition as a 200-byte gather)
  //   χ → permute/not/and/xor (reused; the sole nonlinear step, kept visible)
  //   ι → keccak.iota@1   (custom; XOR RC[round] from aux into lane 0)
  // Padding is keccak.pad@1 (pad10*1 + domain byte), NOT SHA-256's
  // pad-with-byte + length suffix. `rotate-lanes@1` is generic (bare name);
  // the keccak.* steps are Keccak-specific. See src/ciphers/sha3-256.ts.
  r.register("rotate-lanes@1", {
    kind: "ported",
    executor: rotateLanes,
    shape: rotateLanesPortContract,
    doc: rotateLanesDoc,
  });
  r.register("keccak.theta@1", {
    kind: "ported",
    executor: keccakTheta,
    shape: keccakThetaPortContract,
    doc: keccakThetaDoc,
  });
  r.register("keccak.iota@1", {
    kind: "ported",
    executor: keccakIota,
    shape: keccakIotaPortContract,
    meta: keccakIotaMeta,
    doc: keccakIotaDoc,
  });
  r.register("keccak.pad@1", {
    kind: "ported",
    executor: keccakPad,
    shape: keccakPadPortContract,
    doc: keccakPadDoc,
  });
  // ─── Port-native primitives (universal-port plan Phase 2, Slice 2.1a+) ──
  // Authored against the port-native contract directly — no `meta` projection
  // sidecar. Their inputs come entirely from the spec edge graph: a spec must
  // wire every input port via `portInputs`, or the runtime throws "input port
  // X is not wired". SHA-256 was the first shipped consumer. This block is the
  // long-term home for primitives lifted out of cipher-specific implementations
  // as the migration progresses.
  //
  // **Naming convention (intentional).** Port-native primitives drop the
  // `generic.` prefix that every shipped step type uses today. The
  // ABSENCE of a prefix is the signal that this step type is part of
  // the new port-native vocabulary that Phase 3+ rebuilds will compose
  // from. Per-cipher friendly names ride along via the spec leaf's
  // `narrationOverride` field. See `src/steps/CLAUDE.md` "Naming
  // conventions" for the full rule.
  //
  // **Slice 2.1b (2026-05-24)** adds two more port-native primitives:
  // `xor@1` (N-way bitwise XOR, operand0..operand{N-1}) and
  // `add-mod-32@1` (N-way modular addition over 32-bit BE word arrays,
  // operand0..operand{N-1}). Both ship N-way from the start — the plan
  // specified 2-way for add-mod-32 but the user-picked Fork 2 (2026-05-
  // 24) chose N-way for symmetry with xor and for SHA-256's 5-operand
  // T1 update reading as one node. Both reach the same dispatch-path
  // guards as rotate-bits-right@1 (off-flag: "requires
  // portedDispatchEnabled: true"; on-flag without spec edge-wiring:
  // "requires spec edge-wiring (Slice 2.6+)"). Together with
  // rotate-bits-right@1, the SHA-256 message-schedule + compression-
  // function arithmetic surface is complete for the Slice 2.5 build.
  //
  // **Slice 2.3 (2026-05-24)** adds the two boolean primitives Ch/Maj
  // decompose into: `and@1` (N-way bitwise AND, mirrors `xor@1`'s N≥1
  // floor) and `not@1` (1-in 1-out bitwise complement, no params). Per
  // Open #N3 user pick (b) Compositions — SHA-256 helpers Σ0/Σ1/Ch/Maj
  // are expressed in the spec as compositions of these universal
  // primitives instead of cipher-specific step types. Both reach the
  // same dispatch-path guards. Maj's XOR form `(x∧y) ⊕ (x∧z) ⊕ (y∧z)`
  // intentionally avoids needing `or@1` so SHA-256 ships with exactly
  // two new primitives this slice, not three.
  //
  // **Slice 2.4 (2026-05-24)** adds the three SHA-256-preprocessing
  // primitives chosen by user picks at slice start:
  //   - `pad-with-byte@1` (sentinel byte + zero fill to `padTarget` mod
  //     `blockSize`) — user pick (a) Decompose for "padding shape".
  //   - `append-be64-length@1` (8-byte BE encoding of original message
  //     bit-length, via separate `length-source` port) — companion
  //     primitive for the FIPS 180-4 §5.1.1 length suffix.
  //   - `constant-load@1` (zero-input emitter of a declared byte
  //     sequence; output byteLength known at spec time) — user pick (b)
  //     Open #N2 at "72 leaves" granularity (8 H + 64 K for SHA-256).
  // All three reach the same dispatch-path guards. The SHA-256 build at
  // Slice 2.6 wires the padding chain (pad-with-byte → append-be64-
  // length) plus 72 constant-load leaves (8 H + 64 K). `constant-load@1`
  // is also the first port-native primitive whose output byteLength is
  // KNOWN at spec time (declared via function-form PortContract); every
  // prior port-native primitive's output length was polymorphic.
  //
  // **Slice 2.5 (2026-05-25)** adds `shift-bits-right@1` — logical
  // right-shift over each big-endian word, paired with `rotate-bits-
  // right@1` to make SHA-256's σ0/σ1 helpers expressible as
  // compositions per Slice 2.3's (b) Compositions precedent:
  //   σ0(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x)
  //   σ1(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x)
  // The third operand is SHR — NOT a third rotation. This was a plan-
  // prose error caught by the iterative-slice-review pre-authoring
  // check; an earlier draft said "ROR 7/18/3 and ROR 17/19/10". SHR
  // also lands for ChaCha20 / BLAKE2 rebuilds in their future phases.
  r.register("rotate-bits-right@1", {
    kind: "ported",
    executor: rotateBitsRight,
    shape: rotateBitsRightPortContract,
    doc: rotateBitsRightDoc,
  });
  r.register("xor@1", {
    kind: "ported",
    executor: xor,
    shape: xorPortContract,
    doc: xorDoc,
  });
  r.register("add-mod-32@1", {
    kind: "ported",
    executor: addMod32,
    shape: addMod32PortContract,
    doc: addMod32Doc,
  });
  // K2a (2026-06-01): the 16-bit dual of add-mod-32@1, shipped for the
  // Speck32/64 key-schedule decomposition. Same N-way operand convention;
  // multiple-of-2 byteLength invariant. Per-width fixed step types (not a
  // wordBits-parameterized add-mod@1) preserve the "carry semantics differs
  // per width" pedagogy — same posture as add-mod-32 / future add-mod-64.
  r.register("add-mod-16@1", {
    kind: "ported",
    executor: addMod16,
    shape: addMod16PortContract,
    doc: addMod16Doc,
  });
  r.register("and@1", {
    kind: "ported",
    executor: and,
    shape: andPortContract,
    doc: andDoc,
  });
  r.register("not@1", {
    kind: "ported",
    executor: not,
    shape: notPortContract,
    doc: notDoc,
  });
  r.register("pad-with-byte@1", {
    kind: "ported",
    executor: padWithByte,
    shape: padWithBytePortContract,
    doc: padWithByteDoc,
  });
  r.register("append-be64-length@1", {
    kind: "ported",
    executor: appendBe64Length,
    shape: appendBe64LengthPortContract,
    doc: appendBe64LengthDoc,
  });
  r.register("constant-load@1", {
    kind: "ported",
    executor: constantLoad,
    shape: constantLoadPortContract,
    doc: constantLoadDoc,
  });
  r.register("shift-bits-right@1", {
    kind: "ported",
    executor: shiftBitsRight,
    shape: shiftBitsRightPortContract,
    doc: shiftBitsRightDoc,
  });
  // ─── RSA big-integer primitives (docs/plans/shimmying-booping-moth.md) ────
  // Port-native, `bigint`-internal, big-endian. `mul`/`sub` build the
  // key-generation derivation (n = p·q, φ = (p-1)(q-1)); `mod-inverse` derives
  // d = e⁻¹ mod φ; `mod-mul` is the square-and-multiply workhorse (squaring =
  // wire both factors to one source); `cond-mod-mul` is the live-editable
  // conditional multiply driven by one exponent bit per rung. All pure (no
  // meta) — the flat Phase-1 RSA spec fans n/φ/d port-to-port among same-scope
  // siblings; no aux broadcast.
  r.register("mul@1", {
    kind: "ported",
    executor: mul,
    shape: mulPortContract,
    doc: mulDoc,
  });
  r.register("sub@1", {
    kind: "ported",
    executor: sub,
    shape: subPortContract,
    doc: subDoc,
  });
  r.register("mod-mul@1", {
    kind: "ported",
    executor: modMul,
    shape: modMulPortContract,
    doc: modMulDoc,
  });
  r.register("cond-mod-mul@1", {
    kind: "ported",
    executor: condModMul,
    shape: condModMulPortContract,
    doc: condModMulDoc,
  });
  r.register("mod-inverse@1", {
    kind: "ported",
    executor: modInverse,
    shape: modInversePortContract,
    doc: modInverseDoc,
  });
  // `eea-step@1` / `eea-extract@1` (RSA Phase 4): the DECOMPOSITION of the
  // `mod-inverse@1` oracle into a traced extended-Euclid loop. The shipped RSA
  // spec chains `eeaMaxIterations(W)` `eea-step` rungs (one division step per
  // frame, the (r, newR, t, newT) tuple carried port-to-port, the Bézout
  // coefficient kept reduced mod φ so every port stays non-negative) and
  // terminates with `eea-extract` (gcd gate → d). `mod-inverse@1` stays
  // registered above as the FIPS-style oracle the Phase-4 test cross-checks
  // against (same posture as the four key-expansion oracles kept after their
  // schedules decomposed) — no shipped spec emits it anymore.
  r.register("eea-step@1", {
    kind: "ported",
    executor: eeaStep,
    shape: eeaStepPortContract,
    doc: eeaStepDoc,
  });
  r.register("eea-extract@1", {
    kind: "ported",
    executor: eeaExtract,
    shape: eeaExtractPortContract,
    doc: eeaExtractDoc,
  });
  // `rsa.publish-key-params@1` (RSA Phase 2): the one meta-bearing tail of the
  // "Key Generation" group. Identity passthrough whose `meta.auxWritePorts`
  // mirrors the derived n / e / d into `aux["rsa.n" | "rsa.e" | "rsa.d"]`, so
  // the exponentiation ladder (outside the group) reads them back across the
  // group-scope wall via top-level `aux-load-bytes@1` loaders. Same B-minimal
  // posture as the four publish-round-keys tails; the n = p·q / φ = (p-1)(q-1)
  // / d = e⁻¹ mod φ math stays visible as port-native frames above it.
  r.register("rsa.publish-key-params@1", {
    kind: "ported",
    executor: publishKeyParams,
    shape: publishKeyParamsPortContract,
    meta: publishKeyParamsMeta,
    doc: publishKeyParamsDoc,
  });
  // ─── AES round primitives (Slice B1.1 — scaffolding-suppression Phase B) ─
  // Byte-native replacements for the matrix round body. `byte-substitute@1`
  // (SubBytes), `permute@1` (ShiftRows), `gf-matrix-multiply@1` (MixColumns)
  // each do the identical math the legacy `generic.byte-substitution@1` /
  // `generic.shift-rows@1` / `generic.mix-columns@1` did, but on a flat
  // `Uint8Array` with `layout:"raw"` ports — so they stay off the A4
  // `NON_BYTES_ALLOWLIST` (the matrix lifts get removed from it when ECB/CBC
  // are converted in B1.4). AddRoundKey is `xor-with-aux@1` (Finding F3,
  // 2026-05-30) — a single port-native step that reads its `roundKey.N` from
  // aux internally, replacing the earlier `aux-load-bytes@1` (fetch-rk) +
  // `xor@1` pair so the graph reads AddRoundKey as one FIPS-197 §5.1.4 op.
  r.register("byte-substitute@1", {
    kind: "ported",
    executor: byteSubstitute,
    shape: byteSubstitutePortContract,
    doc: byteSubstituteDoc,
  });
  r.register("permute@1", {
    kind: "ported",
    executor: permute,
    shape: permutePortContract,
    doc: permuteDoc,
  });
  r.register("gf-matrix-multiply@1", {
    kind: "ported",
    executor: gfMatrixMultiply,
    shape: gfMatrixMultiplyPortContract,
    doc: gfMatrixMultiplyDoc,
  });
  // @2 (Twofish, 2026-07-12): generalizes @1 with a `fieldModulus` param so the
  // same column-mixing primitive works over Twofish's MDS field GF(2⁸)/0x169
  // (default 0x11B reproduces AES for parity). @1 is left untouched — AES
  // depends on its hardcoded field. Backed by `gfMulPoly` in core/state/matrix.
  r.register("gf-matrix-multiply@2", {
    kind: "ported",
    executor: gfMatrixMultiplyV2,
    shape: gfMatrixMultiplyV2PortContract,
    doc: gfMatrixMultiplyV2Doc,
  });
  // AddRoundKey: XOR the round key (read from `aux["roundKey.N"]` internally
  // via `meta.auxReadPorts`) into the carried `input` port. Hybrid ported
  // shape (executor + meta, no legacy) — same registration posture as
  // `aux-load-bytes@1`. Raw-only ports → off the A4 allowlist.
  r.register("xor-with-aux@1", {
    kind: "ported",
    executor: xorWithAux,
    shape: xorWithAuxPortContract,
    meta: xorWithAuxMeta,
    doc: xorWithAuxDoc,
  });
  // ─── Port-native bridges (Slice 2.6b — universal-port plan) ────────────
  // Three port-native primitives that bridge between the port-native
  // dataflow surface and the runtime `state` variable.
  //
  // `concat@1`: N-way byte concatenation — N input ports, one output port
  // whose byteLength is the sum of input byteLengths. Pure port-native
  // (no meta). First consumer: SHA-256's H||W state assembly between
  // message schedule and compression.
  //
  // `state-to-bytes@1` + `bytes-to-state@1`: symmetric pair bridging
  // `state` ↔ port. Registered as `kind: "ported"` with `meta` but NO
  // `legacy` — they exercise the hybrid "port-native + projection
  // metadata" shape Slice 2.1a's contract widening enabled. The runtime
  // uses `meta.stateInputPort` / `meta.stateOutputPort` to drive the
  // state read/write at leaf invocation; the executor itself is identity
  // passthrough on the port layer (state plumbing is a runtime concern,
  // not an executor concern).
  //
  // Why bridges rather than widening port-native primitives: pure port-
  // native primitives describe their surface entirely via PortContract.
  // Adding state read/write capabilities would conflate "what bytes flow
  // through" (the port layer) with "side effects on runtime state" (a
  // separate axis). The bridge primitives keep those axes orthogonal —
  // any port-native chain can opt into state interactions by composing
  // with these bridges at its boundaries.
  r.register("concat@1", {
    kind: "ported",
    executor: concat,
    shape: concatPortContract,
    doc: concatDoc,
  });
  r.register("state-to-bytes@1", {
    kind: "ported",
    executor: stateToBytes,
    shape: stateToBytesPortContract,
    meta: stateToBytesMeta,
    doc: stateToBytesDoc,
  });
  r.register("bytes-to-state@1", {
    kind: "ported",
    executor: bytesToState,
    shape: bytesToStatePortContract,
    meta: bytesToStateMeta,
    doc: bytesToStateDoc,
  });
  // ─── Aux→port bridge (Slice 2.6d — universal-port plan) ────────────────
  // `aux-load-bytes@1`: read bytes from `aux[params.auxName]` and emit
  // them on the `output` port. Same hybrid registration shape as
  // `state-to-bytes@1` / `bytes-to-state@1` — `kind: "ported"` with `meta`
  // but NO `legacy` executor. The runtime sees `meta.auxReadPorts` and
  // projects `aux[auxName]` into the `input` port BEFORE the executor
  // runs; the executor itself is identity-on-port. First consumers: the
  // decomposed SHA-256 spec's per-round K-table read, the final-add
  // step's H-table read, and (under user pick Q1 = (b)) the per-round
  // W-table read.
  //
  // **Hybrid shape rationale.** Pure port-native primitives describe
  // their surface entirely via PortContract — they have no built-in
  // access to aux. Lifting aux access via metadata (the same path
  // `iv-load` / `aux-load` use, except those are lifted-legacy) keeps
  // "what bytes flow through" (the port layer) orthogonal from "what
  // aux keys are read" (the projection metadata). Spec authors stay in
  // the port-native dataflow surface; the metadata is invisible to the
  // wiring grammar.
  r.register("aux-load-bytes@1", {
    kind: "ported",
    executor: auxLoadBytes,
    shape: auxLoadBytesPortContract,
    meta: auxLoadBytesMeta,
    doc: auxLoadBytesDoc,
  });
  // `byte-slice@1`: extract a contiguous byte range from the input port
  // at a parameterized offset. Pure port-native — no `meta`, no `legacy`.
  // PortContract declares both input.byteLength (= params.sourceByteLength)
  // and output.byteLength (= params.length) — exact lengths drive the
  // editor's coercion-warning glyphs. First consumers: SHA-256's per-round
  // K_t extraction from the 256-byte K-table (and W_t from W under user
  // pick Q1 = (b)). Paired with `split-bytes@1` (next register block) —
  // byte-slice handles arbitrary-offset single-range extraction;
  // split-bytes handles symmetric N-way extraction starting at offset 0.
  r.register("byte-slice@1", {
    kind: "ported",
    executor: byteSlice,
    shape: byteSlicePortContract,
    doc: byteSliceDoc,
  });
  // `split-bytes@1`: symmetric inverse of `concat@1`. One input port,
  // N output ports named `output0`..`output{N-1}`. Each output's
  // byteLength comes from the corresponding entry in `params.widths`;
  // input byteLength = sum(widths). Pure port-native — no `meta`, no
  // `legacy`. First consumers: SHA-256's per-round working-variable
  // extraction (32 bytes → 8 × 4-byte words a..h) and the final-add
  // step's H-table extraction (32 bytes → H_0..H_7). Symmetric N-way at
  // offset 0 is the ergonomic case here; arbitrary-offset single-range
  // extraction is `byte-slice@1`'s job.
  r.register("split-bytes@1", {
    kind: "ported",
    executor: splitBytes,
    shape: splitBytesPortContract,
    doc: splitBytesDoc,
  });
  // The monolithic SHA-256 helpers (sha2.message-schedule-step@1 /
  // compression-round@1 / final-add@1) were the Slice 2.6b coarse-grained
  // lifts, superseded by the Slice 2.6d port-native decomposition of
  // SHA-256 into the universal vocabulary (rotate/shift/xor/add/and/not +
  // the bridge primitives). With no shipped spec referencing them, they
  // were retired in Phase 5 Slice 5.1 (2026-05-30).
  return r;
};
