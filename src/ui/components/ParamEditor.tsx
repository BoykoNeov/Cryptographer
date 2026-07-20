/**
 * Top-level params editor. Looks at the currently selected step (whatever
 * frame the timeline is parked on) and dispatches to a per-step-type
 * sub-editor: 16x16 grid for S-boxes, 4x4 for MixColumns, etc.
 *
 * The "Apply to all" button below each editor propagates the same params
 * to every step of the same type — useful when changing "the AES S-box"
 * (which the architecture stores as 10 separate copies, one per round).
 *
 * Editing flows: ParamEditor → spec store mutator → spec signal updates →
 * createEffect in App.tsx detects the change → debounced re-run → trace
 * updates → matrix view re-renders. No imperative re-run call from here.
 */

import { formatBytes } from "@/core/format";
import { findStep } from "@/core/spec-mutations";
import { gfMatInverse4x4 } from "@/core/state/gf-matrix";
import type { Json, StepLeaf, StepNode } from "@/core/types";
import { For, Index, Match, Show, Switch, createMemo, createSignal } from "solid-js";
import {
  editAllStepsByType,
  editStepParams,
  removeStepFromSpec,
  syncMixColumnsInverseToCounterpart,
  syncSboxCopyToCounterpart,
  syncSboxInverseToCounterpart,
  syncSboxInverseToCounterpartByIndex,
  useMode,
  useSpec,
} from "../stores/spec";
import { ActionButton } from "./ActionButton";
import { ByteCellInput } from "./ByteCellInput";
import { MatrixEditor } from "./MatrixEditor";
import { SboxEditor } from "./SboxEditor";
import { ShiftsEditor } from "./ShiftsEditor";
import { isKeyScheduleLeafId, isRoundBodyLeafId } from "./cross-mode-mirror-registry";
import {
  collisionGroupsByIndex,
  countRedundantDuplicates,
  findDuplicateIndices,
  invertSbox,
  repairToPermutation,
} from "./sbox-validation";

type Props = {
  /**
   * The id of the step we should be editing. Decoupled from the trace
   * frame so freshly-inserted steps (palette drops, with empty params and
   * no executed frame yet) are immediately editable, and so steps that
   * never executed (e.g. an upstream step threw) remain reachable through
   * a graph-view click. The id is resolved against the live spec via
   * `findStep`, so the spec — not the trace — is the source of truth.
   */
  stepId: string | null;
};

export const ParamEditor = (props: Props) => {
  const spec = useSpec();

  // Resolve the stepId to a live spec leaf. Returns null if the id is null
  // or no longer present in the spec (e.g. the user deleted it from
  // another surface). The Show below renders the "no step selected"
  // fallback in both cases.
  const step = (): StepLeaf | null => {
    const id = props.stepId;
    if (!id) return null;
    return findStep(spec(), id);
  };

  const matchingSteps = (): number => {
    const s = step();
    if (!s) return 0;
    // Count how many leaves share this step's type — used by the
    // "Apply to all N steps" button label.
    //
    // Must descend into every container kind: `group`, `iterate` (same
    // `.children` shape), AND `feistel-round` (which exposes
    // `.tracks[*].children` instead). Pre-DES this only handled `group`
    // — so an iterate-bound leaf would under-count (latent gap; no
    // shipped cipher exercised it) and a feistel-round-bound leaf would
    // miss entirely. Both fixed here in the same walker so future
    // container kinds can be added without re-discovering the pattern.
    let count = 0;
    const visit = (nodes: readonly StepNode[]): void => {
      for (const node of nodes) {
        if (node.kind === "step") {
          if (node.type === s.type) count++;
        } else {
          visit(node.children);
        }
      }
    };
    visit(spec().steps);
    return count;
  };

  return (
    <Show when={step()} fallback={<div class="muted">no step selected</div>}>
      {(getStep) => (
        <div class="param-editor">
          <div class="param-editor-header">
            <span class="param-editor-title">params · {getStep().id}</span>
            <span class="param-editor-type">{getStep().type}</span>
          </div>

          <Switch
            fallback={
              <div class="muted small">
                no editor for step type {getStep().type} (raw params view)
                <pre class="param-raw">{JSON.stringify(getStep().params, null, 2)}</pre>
              </div>
            }
          >
            <Match when={getStep().type === "generic.byte-substitution@1"}>
              <SbxBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "generic.mix-columns@1"}>
              <MixBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "generic.shift-rows@1"}>
              <ShiftsBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match
              when={
                getStep().type === "aes.key-expansion@1" || getStep().type === "aes.key-expansion@2"
              }
            >
              <KeyExpansionBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "generic.add-round-key@1"}>
              <AddRoundKeyBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={BLOCK_SIZE_PARAM_TYPES.has(getStep().type)}>
              <BlockSizeBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            {/*
              K2c (2026-06-01) — retired `SpeckKeyScheduleBlock` after the
              A-vs-B gate AskUserQuestion picked "retire now." No shipped
              Speck spec contains a `speck.key-schedule@1` leaf since K2a
              (the four BE/LE × encrypt/decrypt specs all route through the
              decomposed `key-schedule` group built by
              `buildSpeck32_64KeyScheduleNative`). The legacy executor + its
              StepDocumentation stay registered in `default-registry.ts`
              for two reasons: it's the KAT oracle for
              `tests/speck-32-64-key-schedule-decomposition.test.ts`, and a
              pre-K2 saved doc carrying the monolithic leaf can still load
              + encrypt. Such a doc now shows the raw-JSON fallback panel
              when selected (rare path; "loads and runs" but no bespoke
              editor) — re-selecting the cipher regenerates the decomposed
              schedule. The block's drop from this Switch is the visible
              half of the retire.
             */}
            <Match
              when={
                getStep().type === "speck.round@1" || getStep().type === "speck.round-inverse@1"
              }
            >
              <SpeckRoundBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "serpent.key-expansion@1"}>
              <SerpentKeyExpansionBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "serpent.bit-permutation@1"}>
              <SerpentBitPermutationBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "serpent.add-round-key@1"}>
              <SerpentAddRoundKeyBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "serpent.sub-bytes@1"}>
              <SerpentSubBytesBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match
              when={
                getStep().type === "serpent.linear-transform@1" ||
                getStep().type === "serpent.inv-linear-transform@1"
              }
            >
              <NoParamsBlock label="Linear transform has no editable parameters." />
            </Match>
            <Match when={getStep().type === "des.key-schedule@1"}>
              <DesKeyScheduleBlock step={getStep()} />
            </Match>
            <Match
              when={
                getStep().type === "des.initial-permutation@1" ||
                getStep().type === "des.final-permutation@1" ||
                getStep().type === "des.expand-R@1" ||
                getStep().type === "des.p-permutation@1" ||
                getStep().type === "des.bit-permute@1"
              }
            >
              {/* `des.bit-permute@1` (key-schedule PC-1/PC-2, K4a) reuses the
                  read-only table view — same `table` param; the "Output bits"
                  row (table().length) distinguishes PC-1's 56 from PC-2's 48. */}
              <DesPermutationBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "des.rotate-halves@1"}>
              <DesRotateHalvesBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "des.publish-round-keys@1"}>
              <DesPublishRoundKeysBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "des.xor-with-K@1"}>
              <DesXorWithKBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "des.s-boxes@1"}>
              <DesSBoxesBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "generic.aux-load@1"}>
              <AuxLoadBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "generic.aux-xor@1"}>
              <AuxXorBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "generic.aux-copy@1"}>
              <AuxCopyBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "generic.iv-load@1"}>
              <IvLoadBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "generic.xor-aux-into-state@1"}>
              <XorAuxIntoStateBlock step={getStep()} />
            </Match>
            <Match
              when={
                getStep().type === "generic.state-to-aux@1" ||
                getStep().type === "generic.state-to-aux-bytes@1"
              }
            >
              <StateToAuxBlock step={getStep()} />
            </Match>
            {/* ─── Byte-native AES round primitives (Slice B1 —
                scaffolding-suppression Phase B). They reuse the same
                SboxEditor/MatrixEditor the matrix `generic.*` steps use, but
                deliberately OMIT the cross-mode sync rows that SbxBlock/
                MixBlock carry: the decrypt counterpart is still the matrix
                step until B1.2/B1.4, so a same-type sync button would write to
                zero steps on the matrix side — a false affordance. The mirror
                entry ships in B1.2 once both modes share the byte-native type. */}
            <Match when={getStep().type === "byte-substitute@1"}>
              <ByteSubstituteBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "gf-matrix-multiply@1"}>
              <GfMatrixMultiplyBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "gf-matrix-multiply@2"}>
              <GfMatrixMultiplyV2Block step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "permute@1"}>
              <PermuteBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "xor-with-aux@1"}>
              {/* Byte-native AddRoundKey (Finding F3): one read-only `auxName`
                  scalar ("roundKey.N"). Reuses AddRoundKeyBlock — same param,
                  same no-ApplyAllRow reasoning (each round references a
                  distinct round key). */}
              <AddRoundKeyBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            {/* ─── Port-native primitives (Slice S1 of sha-256-density-polish) ── */}
            <Match
              when={
                getStep().type === "rotate-bits-right@1" || getStep().type === "shift-bits-right@1"
              }
            >
              <BitOpBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={INPUT_COUNT_PARAM_TYPES.has(getStep().type)}>
              <InputCountBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "byte-slice@1"}>
              <ByteSliceBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "aux-load-bytes@1"}>
              <AuxLoadBytesBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "split-bytes@1"}>
              <SplitBytesBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "constant-load@1"}>
              <ConstantLoadBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "aes.publish-round-keys@1"}>
              <PublishRoundKeysBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "speck.publish-round-keys@1"}>
              {/*
                K2a (2026-06-01): the Speck publish tail's params shape
                (outputPrefix, rounds) is identical to AES's, so it reuses
                PublishRoundKeysBlock unchanged. The structural deltas
                (round-key count, byteLength) are in the executor + port
                contract, not surfaced through the editor.
              */}
              <PublishRoundKeysBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "serpent.publish-round-keys@1"}>
              {/*
                K3a (2026-06-02): the Serpent publish tail uses a `count`
                param (fixed 33), not AES/Speck's `rounds`, so it gets a thin
                dedicated read-only block rather than reusing
                PublishRoundKeysBlock (which renders `rounds + 1`).
              */}
              <SerpentPublishRoundKeysBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "serpent.key-sbox@1"}>
              <SerpentKeySboxBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "blowfish.key-schedule@1"}>
              <BlowfishKeyScheduleBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "twofish.h-expand@1"}>
              <TwofishHExpandBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "twofish.sbox-lookup@1"}>
              <TwofishSboxLookupBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "twofish.publish-subkeys@1"}>
              <TwofishPublishSubkeysBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "blowfish.sbox-lookup@1"}>
              <BlowfishSboxLookupBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "rsa.publish-key-params@1"}>
              {/*
                RSA Phase 2 (2026-06-08): the Key-Generation group's publish
                tail. Named (n/e/d), not indexed like the round-key tails, so
                it gets its own thin read-only block rather than reusing
                PublishRoundKeysBlock.
              */}
              <RsaPublishKeyParamsBlock step={getStep()} />
            </Match>
            <Match when={getStep().type === "pad-with-byte@1"}>
              <PadWithByteBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={KECCAK_SCALAR_PARAM_TYPES.has(getStep().type)}>
              <KeccakParamsBlock step={getStep()} />
            </Match>
            <Match when={SP800185_SCALAR_PARAM_TYPES.has(getStep().type)}>
              <Sp800185ParamsBlock step={getStep()} />
            </Match>
            <Match when={NO_PARAMS_PORT_NATIVE_TYPES.has(getStep().type)}>
              <NoParamsBlock label={portNativeNoParamsLabel(getStep().type)} />
            </Match>
          </Switch>

          {/* Delete affordance. Sits at the bottom of the editor so it
              doesn't compete with per-block "Apply to all" rows. No
              confirmation dialog — the cipher pedagogy is "experiment
              freely, see what breaks"; an accidental delete is recovered
              by dragging the step back in from the palette. The button
              is intentionally low-emphasis (no .danger class) to keep
              the editor feeling like a workbench, not a tribunal. */}
          <div class="param-editor-footer">
            <button
              type="button"
              class="param-editor-delete"
              data-testid="param-editor-delete"
              onClick={() => removeStepFromSpec(getStep().id)}
              title={`Remove ${getStep().id} from the spec`}
            >
              Delete this step
            </button>
          </div>
        </div>
      )}
    </Show>
  );
};

// ─── Per-step-type editor blocks ─────────────────────────────────────────
// Each one knows the param shape for its step type, owns its "Apply to all"
// button, and writes through the spec store. Kept small + similar so the
// pattern is obvious when adding the next step type.

type BlockProps = { step: StepLeaf; matchingCount: number };

const SbxBlock = (props: BlockProps) => {
  const sbox = (): readonly number[] =>
    ((props.step.params as { sbox?: number[] }).sbox ?? []) as readonly number[];

  return (
    <>
      <SboxEditor
        sbox={sbox()}
        onChange={(next) => {
          // Replace just this step's S-box. The user must explicitly hit
          // "Apply to all" to propagate.
          // params is typed as Json (which may be a primitive) but we know
          // these step types always have object params.
          editStepParams(props.step.id, {
            ...(props.step.params as Record<string, Json>),
            sbox: next,
          });
        }}
      />
      <ApplyAllRow
        currentParams={props.step.params}
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        label="S-box"
      />
      {/* Cross-mode mirror — only on `generic.byte-substitution@1` (the
          AES SubBytes step type). Key-expansion's S-box editor below
          deliberately omits this: FIPS-197 §5.2 says key expansion uses
          the FORWARD S-box even when decrypting, so a "sync inverse"
          would be wrong there. That step needs a different operation
          ("copy, don't invert"), which we'll surface separately when
          there's user demand. */}
      <SyncInverseRow currentSbox={sbox()} stepType={props.step.type} />
    </>
  );
};

const MixBlock = (props: BlockProps) => {
  const matrix = (): readonly (readonly number[])[] =>
    (props.step.params as { matrix?: number[][] }).matrix ?? [];

  return (
    <>
      <MatrixEditor
        matrix={matrix()}
        onChange={(next) => {
          editStepParams(props.step.id, {
            ...(props.step.params as Record<string, Json>),
            matrix: next,
          });
        }}
      />
      <ApplyAllRow
        currentParams={props.step.params}
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        label="MixColumns matrix"
      />
      {/* Class-2 (inverse) cross-mode mirror. Appended outside any
          <details>, so no orphaning concern. The Sync row encapsulates
          its own GF(2^8) invertibility check via try/catch around
          `gfMatInverse4x4`. */}
      <SyncMixColumnsRow currentMatrix={matrix()} stepType={props.step.type} />
    </>
  );
};

const ShiftsBlock = (props: BlockProps) => {
  const shifts = (): readonly number[] =>
    ((props.step.params as { shifts?: number[] }).shifts ?? []) as readonly number[];

  return (
    <>
      <ShiftsEditor
        shifts={shifts()}
        onChange={(next) => {
          editStepParams(props.step.id, {
            ...(props.step.params as Record<string, Json>),
            shifts: next,
          });
        }}
      />
      <ApplyAllRow
        currentParams={props.step.params}
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        label="row shifts"
      />
    </>
  );
};

// ─── Byte-native AES round primitives (Slice B1 — scaffolding-suppression
// Phase B) ───────────────────────────────────────────────────────────────
// These reuse the shared SboxEditor / MatrixEditor and the ApplyAllRow, and
// — as of Slice B1.2, when AES-128 decrypt also went byte-native — carry the
// SAME cross-mode sync rows SbxBlock / MixBlock carry. Both modes now share
// the byte-native `byte-substitute@1` / `gf-matrix-multiply@1` type, so the
// single-stepType `syncSboxInverseToCounterpart` /
// `syncMixColumnsInverseToCounterpart` broadcast lands on the real decrypt
// counterpart (in B1.1, when only encrypt was byte-native, the sync would
// have written to zero steps — a false affordance — so the rows were
// deferred to B1.2 along with their `cross-mode-mirror-registry.ts` entries).

// SubBytes on a flat 16-byte array. Same `params.sbox` (256 entries) as the
// matrix `generic.byte-substitution@1`, so the SboxEditor renders unchanged.
const ByteSubstituteBlock = (props: BlockProps) => {
  const sbox = (): readonly number[] =>
    ((props.step.params as { sbox?: number[] }).sbox ?? []) as readonly number[];
  // Role-scope by leaf id (key-schedule-decomposition K1c): `byte-substitute@1`
  // is BOTH round-body SubBytes AND key-schedule SubWord. Round-body SubBytes
  // is the class-2 inverse mirror (encrypt forward / decrypt inverse); the
  // key-schedule SubWord is the class-1 identity Copy (forward S-box on both
  // sides, FIPS-197 §5.2). Rendering the wrong row — and, worse, letting its
  // mutator broadcast type-wide — would corrupt the decrypt key schedule, so
  // we pick the row AND pass the matching `idFilter` to confine the write.
  const isKeySchedule = (): boolean => isKeyScheduleLeafId(props.step.id);

  return (
    <>
      <SboxEditor
        sbox={sbox()}
        onChange={(next) => {
          editStepParams(props.step.id, {
            ...(props.step.params as Record<string, Json>),
            sbox: next,
          });
        }}
      />
      <ApplyAllRow
        currentParams={props.step.params}
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        label="S-box"
      />
      <Show
        when={isKeySchedule()}
        fallback={
          /* Round-body SubBytes — class-2 (inverse) cross-mode mirror.
             Scoped to NON-key-schedule leaves so the inverse never lands on
             the SubWord leaves. */
          <SyncInverseRow
            currentSbox={sbox()}
            stepType={props.step.type}
            idFilter={isRoundBodyLeafId}
          />
        }
      >
        {/* Key-schedule SubWord — class-1 (identity) Copy mirror. The
            schedule uses the FORWARD S-box even when decrypting (FIPS-197
            §5.2), so encrypt and decrypt hold the SAME table. Scoped to the
            key-schedule leaves. (Re-homed here from the retired
            `aes.key-expansion@1/@2` KeyExpansionBlock Copy row.) */}
        <CopySboxRow
          currentSbox={sbox()}
          stepType={props.step.type}
          idFilter={isKeyScheduleLeafId}
        />
      </Show>
    </>
  );
};

// MixColumns as a GF(2^8) matrix multiply on a flat 16-byte array. Same
// `params.matrix` (4×4) as the matrix `generic.mix-columns@1`.
const GfMatrixMultiplyBlock = (props: BlockProps) => {
  const matrix = (): readonly (readonly number[])[] =>
    (props.step.params as { matrix?: number[][] }).matrix ?? [];

  return (
    <>
      <MatrixEditor
        matrix={matrix()}
        onChange={(next) => {
          editStepParams(props.step.id, {
            ...(props.step.params as Record<string, Json>),
            matrix: next,
          });
        }}
      />
      <ApplyAllRow
        currentParams={props.step.params}
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        label="MixColumns matrix"
      />
      {/* Class-2 (inverse) cross-mode mirror — encrypt holds AES_MIX_MATRIX,
          decrypt holds its GF(2⁸) inverse. Both AES-128 modes byte-native as
          of Slice B1.2 (see ByteSubstituteBlock above). */}
      <SyncMixColumnsRow currentMatrix={matrix()} stepType={props.step.type} />
    </>
  );
};

// @2 (Twofish MDS): the matrix multiply over an ARBITRARY GF(2⁸) field. Same
// editable 4×4 MatrixEditor as @1 plus a read-only `fieldModulus` scalar (the
// reduction polynomial — Twofish's MDS is 0x169). No cross-mode inverse mirror:
// Twofish's g function (and thus its MDS) is identical in encrypt and decrypt,
// so there is no inverse to sync. ApplyAllRow still broadcasts the matrix across
// the 32 MDS leaves (all share the one MDS matrix).
const GfMatrixMultiplyV2Block = (props: BlockProps) => {
  const matrix = (): readonly (readonly number[])[] =>
    (props.step.params as { matrix?: number[][] }).matrix ?? [];
  const fieldModulus = (): number =>
    (props.step.params as { fieldModulus?: number }).fieldModulus ?? 0x11b;

  return (
    <>
      <MatrixEditor
        matrix={matrix()}
        onChange={(next) => {
          editStepParams(props.step.id, {
            ...(props.step.params as Record<string, Json>),
            matrix: next,
          });
        }}
      />
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Field polynomial</dt>
          <dd>0x{fieldModulus().toString(16)}</dd>
        </div>
      </dl>
      <ApplyAllRow
        currentParams={props.step.params}
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        label="MDS matrix"
      />
    </>
  );
};

// ShiftRows expressed as a flat-byte permutation: `params.indices` is the
// 16-entry column-major source-position table (output byte i ← input byte
// indices[i]). Rendered read-only, like the DES permutation tables — the
// ShiftRows permutation is structural, not a free parameter a learner edits
// cell-by-cell (the matrix form used `shifts`; the byte-native form bakes the
// same rotation into explicit indices).
const PermuteBlock = (props: { step: StepLeaf }) => {
  const indices = (): readonly number[] =>
    ((props.step.params as { indices?: number[] }).indices ?? []) as readonly number[];

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Permutation</dt>
          <dd>ShiftRows (column-major byte indices)</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Output bytes</dt>
          <dd>{indices().length}</dd>
        </div>
      </dl>
      <details class="param-section param-collapsible">
        <summary class="param-section-label">
          Source-index table ({indices().length} entries — click to expand)
        </summary>
        {/* Reuses the serpent-bit-table grid CSS, same as DesPermutationBlock —
            each cell is the source byte position for the output at that slot. */}
        <div class="serpent-bit-table">
          <For each={indices()}>
            {(value, i) => (
              <span class="bit-table-cell" title={`output byte ${i()} ← input byte ${value}`}>
                {value}
              </span>
            )}
          </For>
        </div>
      </details>
    </>
  );
};

// Key-expansion block.
//
// The raw JSON fallback was unusable for this step type — `sbox` (256
// numbers) and `rcon` (~11) pretty-print to hundreds of single-value
// lines. This compact view shows:
//   - scalars (keyAuxName / outputPrefix / rounds) as a read-only dl;
//     editing them by hand reliably breaks the spec (mismatched aux
//     names throw, and the executor asserts `rounds === Nk + 6`).
//   - rcon as a single horizontal row of editable byte cells.
//   - the S-box collapsed inside a <details>, reusing SboxEditor so
//     the affordance is identical to SubBytes.
const KeyExpansionBlock = (props: BlockProps) => {
  const params = (): {
    keyAuxName?: string;
    outputPrefix?: string;
    rounds?: number;
    sbox?: readonly number[];
    rcon?: readonly number[];
  } => props.step.params as never;

  const sbox = (): readonly number[] => params().sbox ?? [];
  const rcon = (): readonly number[] => params().rcon ?? [];

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Input aux</dt>
          <dd>{params().keyAuxName ?? "—"}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Output prefix</dt>
          <dd>{params().outputPrefix ?? "—"}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Rounds (Nr)</dt>
          <dd>{params().rounds ?? "—"}</dd>
        </div>
      </dl>

      <div class="param-section">
        <div class="param-section-label">Rcon (round constants)</div>
        <div class="rcon-row">
          <For each={rcon()}>
            {(value, i) => (
              <ByteCellInput
                value={value}
                onCommit={(next) => {
                  const out = [...rcon()];
                  out[i()] = next;
                  writeParams({ rcon: out });
                }}
              />
            )}
          </For>
        </div>
      </div>

      <details class="param-section param-collapsible">
        <summary class="param-section-label">S-box (256 entries — click to expand)</summary>
        <SboxEditor sbox={sbox()} onChange={(next) => writeParams({ sbox: next })} />
        {/* Sits INSIDE the <details> so the Copy affordance lives next to
            the table it acts on. Outside the collapsible, the button would
            orphan when the section is collapsed (the default state) and
            the user would have no visible link between editing the table
            and the cross-mode operation. */}
        <CopySboxRow currentSbox={sbox()} stepType={props.step.type} />
      </details>

      <ApplyAllRow
        currentParams={props.step.params}
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        label="key-expansion params"
      />
    </>
  );
};

// Padding-family + load/store block-size block.
//
// All of these steps share a single { blockSize: number } param. The raw
// JSON fallback rendered three lines for that one fact. One read-only
// scalar row matches the look of the AddRoundKey block.
//
// Why read-only:
//  - load-block hard-asserts blockSize === 16; anything else throws.
//  - pkcs7-pad / zero-pad / iso7816-4-pad will run with any 1..255 value,
//    but the App's Run handler caps input length based on the *active
//    padding scheme* (paddingLimits in stores/padding.ts), not this
//    param, so editing it here just produces a downstream length mismatch
//    at load-block.
// Multi-block + non-AES block sizes will unlock genuine editability when
// the cipher modes (ECB/CBC/CTR/GCM) feature lands.
const BLOCK_SIZE_PARAM_TYPES = new Set([
  "generic.pkcs7-pad@1",
  "generic.pkcs7-unpad@1",
  "generic.zero-pad@1",
  "generic.zero-unpad@1",
  "generic.iso7816-4-pad@1",
  "generic.iso7816-4-unpad@1",
  "generic.load-block@1",
  "generic.store-block@1",
]);

const BlockSizeBlock = (props: BlockProps) => {
  const params = (): { blockSize?: number } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Block size</dt>
        <dd>{params().blockSize ?? "—"} bytes</dd>
      </div>
    </dl>
  );
};

// SHA-3 / Keccak scalar-param block. `keccak.pad@1` (rate + domain byte),
// `keccak.iota@1` (round index + RC aux slot), and `rotate-lanes@1` (lane
// width + endianness + per-lane offset count) all carry small STRUCTURAL
// params that define the algorithm — editing them would break the FIPS 202
// math — so they render read-only, like the padding block-size row. The 25
// ρ offsets are a fixed table (Table 2), summarized rather than dumped.
const KECCAK_SCALAR_PARAM_TYPES = new Set(["keccak.pad@1", "keccak.iota@1", "rotate-lanes@1"]);

const KeccakParamsBlock = (props: { step: StepLeaf }) => {
  const type = (): string => props.step.type;
  const params = (): {
    rate?: number;
    domainByte?: number;
    round?: number;
    auxName?: string;
    wordBits?: number;
    littleEndian?: boolean;
    offsets?: readonly number[];
  } => props.step.params as never;
  const hex2 = (n: number | undefined): string =>
    n === undefined ? "—" : `0x${n.toString(16).padStart(2, "0")}`;

  return (
    <dl class="param-scalars">
      <Show when={type() === "keccak.pad@1"}>
        <div class="param-scalar-row">
          <dt>Rate</dt>
          <dd>{params().rate ?? "—"} bytes</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Domain byte</dt>
          <dd>{hex2(params().domainByte)} (0x06 = SHA-3, 0x1F = SHAKE)</dd>
        </div>
      </Show>
      <Show when={type() === "keccak.iota@1"}>
        <div class="param-scalar-row">
          <dt>Round</dt>
          <dd>{params().round ?? "—"} (selects RC[round])</dd>
        </div>
        <div class="param-scalar-row">
          <dt>RC slot</dt>
          <dd>aux["{params().auxName ?? "RC"}"]</dd>
        </div>
      </Show>
      <Show when={type() === "rotate-lanes@1"}>
        <div class="param-scalar-row">
          <dt>Lane width</dt>
          <dd>{params().wordBits ?? "—"} bits</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Byte order</dt>
          <dd>{params().littleEndian ? "little-endian (Keccak)" : "big-endian"}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Offsets</dt>
          <dd>{params().offsets?.length ?? 0} lanes (ρ rotation table, FIPS 202 Table 2)</dd>
        </div>
      </Show>
    </dl>
  );
};

// NIST SP 800-185 encoding scalar-param block. `encode-string@1` (no params —
// it reads its input length at run time), `bytepad@1` (block size `w`), and
// `right-encode@1` (the `value` it encodes) carry small STRUCTURAL params that
// define the cSHAKE / KMAC prefix — editing them by hand would break the
// SP 800-185 math — so they render read-only, like the Keccak scalar block.
const SP800185_SCALAR_PARAM_TYPES = new Set(["encode-string@1", "bytepad@1", "right-encode@1"]);

const Sp800185ParamsBlock = (props: { step: StepLeaf }) => {
  const type = (): string => props.step.type;
  const params = (): { w?: number; value?: number } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <Show when={type() === "encode-string@1"}>
        <div class="param-scalar-row">
          <dt>encode_string</dt>
          <dd>left_encode(8·len) ‖ input — no parameters (length read at run time)</dd>
        </div>
      </Show>
      <Show when={type() === "bytepad@1"}>
        <div class="param-scalar-row">
          <dt>Block size w</dt>
          <dd>{params().w ?? "—"} bytes (the sponge rate — pad to a multiple)</dd>
        </div>
      </Show>
      <Show when={type() === "right-encode@1"}>
        <div class="param-scalar-row">
          <dt>Value</dt>
          <dd>{params().value ?? "—"} (bits; 0 = KMACXOF, else output length × 8)</dd>
        </div>
      </Show>
    </dl>
  );
};

// AddRoundKey block.
//
// One param, one string: { auxName: "roundKey.N" }. The raw-JSON fallback
// rendered this as three lines for one fact. Single read-only scalar row
// matches the look of the key-expansion scalars.
//
// No ApplyAllRow: each AddRoundKey step intentionally references a
// DIFFERENT round key (roundKey.0 … roundKey.Nr), and copying one step's
// auxName onto every match would silently XOR the same round key Nr+1
// times and produce wrong ciphertext.
const AddRoundKeyBlock = (props: BlockProps) => {
  const params = (): { auxName?: string } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Round key aux</dt>
        <dd>{params().auxName ?? "—"}</dd>
      </div>
    </dl>
  );
};

// Speck round / round-inverse block.
//
// Five params shared by both forward and inverse steps, split by editability
// (the same rule as the port-native blocks below — editable when an edit
// produces wrong-but-DEFINED output, read-only when it would throw or break
// wiring):
//
//   - `alpha` / `beta` (the ROR/ROL rotation constants) and `byteOrder` (the
//     serialization convention) are EDITABLE. The `speck.round@1` /
//     `speck.round-inverse@1` executors read all three at run time
//     (`src/steps/speck-round.ts`), so editing them just diverges the cipher —
//     "what if Speck rotated by 3 instead of 7?" is exactly the pedagogy. These
//     bare round-body leaves are the ONLY place these params live (the rounds
//     aren't grouped, so no composite/graph affordance reaches them); in-place
//     editing here is the only path to them.
//   - `roundKeyAux` stays READ-ONLY: it's per-round DISTINCT wiring
//     (`roundKey.0` first in encrypt vs `roundKey.21` first in decrypt), so
//     editing/broadcasting it would point rounds at the wrong key. Pinning it
//     visible keeps the key ordering inspectable while scrubbing.
//   - `wordBits` stays READ-ONLY: structural (only 16 ships; the schedule
//     builder throws on ≠16).
//
// The apply-to-all row is SCOPED (`SpeckArxApplyAllRow`) — it broadcasts only
// α/β/byteOrder and PRESERVES each leaf's own `roundKeyAux`, which is why it
// can't reuse the generic `ApplyAllRow` (that copies the whole params object
// and would clobber every round's distinct key wiring).
const SpeckRoundBlock = (props: BlockProps) => {
  const params = (): {
    roundKeyAux?: string;
    alpha?: number;
    beta?: number;
    wordBits?: number;
    byteOrder?: string;
  } => props.step.params as never;
  const alpha = (): number => params().alpha ?? 0;
  const beta = (): number => params().beta ?? 0;
  const wordBits = (): number => params().wordBits ?? 16;
  const byteOrder = (): string => params().byteOrder ?? "be-paper";

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Round key aux</dt>
          <dd>{params().roundKeyAux ?? "—"}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>α (ROR)</dt>
          <dd>
            {/* [1, wordBits-1] matches the key schedule's valid range and
                avoids the degenerate identity rotations (0 / wordBits). */}
            <IntInput
              value={alpha()}
              min={1}
              max={wordBits() - 1}
              placeholder="7"
              onCommit={(next) => writeParams({ alpha: next })}
            />
          </dd>
        </div>
        <div class="param-scalar-row">
          <dt>β (ROL)</dt>
          <dd>
            <IntInput
              value={beta()}
              min={1}
              max={wordBits() - 1}
              placeholder="2"
              onCommit={(next) => writeParams({ beta: next })}
            />
          </dd>
        </div>
        <div class="param-scalar-row">
          <dt>Word bits (n)</dt>
          <dd>{params().wordBits ?? "—"}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Byte order</dt>
          <dd>
            {/* Native select constrained to the two valid conventions, so the
                executor never sees an unknown byteOrder. Both are whole-cipher
                conventions; editing one round diverges (see the note below). */}
            <select
              class="speck-byteorder-select"
              value={byteOrder()}
              onChange={(e) => writeParams({ byteOrder: e.currentTarget.value })}
            >
              <option value="be-paper">be-paper</option>
              <option value="le-nsa">le-nsa</option>
            </select>
          </dd>
        </div>
      </dl>
      <SpeckArxApplyAllRow
        stepType={props.step.type}
        matchingCount={props.matchingCount}
        alpha={alpha()}
        beta={beta()}
        byteOrder={byteOrder()}
      />
      <p class="muted small">
        α and β also drive the key schedule's rotations (in the Key Expansion group). Editing them
        here changes only the round function — the schedule keeps its original rotations, so the
        cipher will diverge from canonical Speck. That's intentional: tinker and watch it break.
      </p>
    </>
  );
};

// Scoped apply-to-all for the Speck ARX constants. Unlike the generic
// `ApplyAllRow` (which replaces the WHOLE params object and would clobber each
// round's distinct `roundKeyAux`), this broadcasts ONLY α/β/byteOrder by
// spreading each leaf's existing params and overriding those three keys —
// `roundKeyAux` (and `wordBits`) survive. Scopes to `stepType` so it stays
// within the active mode's rounds (`speck.round@1` in encrypt,
// `speck.round-inverse@1` in decrypt); the counterpart mode's spec is untouched
// (cross-mode is never auto-synced). Gated `matchingCount > 1` like ApplyAllRow.
const SpeckArxApplyAllRow = (props: {
  stepType: string;
  matchingCount: number;
  alpha: number;
  beta: number;
  byteOrder: string;
}) => (
  <Show when={props.matchingCount > 1}>
    <div class="apply-all-row">
      <ActionButton
        title={`Copy this round's α, β and byte order to all ${props.matchingCount} ${props.stepType} rounds (each round keeps its own round key)`}
        feedbackLabel={`Applied α/β/byte order to all ${props.matchingCount} rounds`}
        onAction={() => {
          editAllStepsByType(props.stepType, (p) => ({
            ...(p as Record<string, Json>),
            alpha: props.alpha,
            beta: props.beta,
            byteOrder: props.byteOrder,
          }));
        }}
      >
        Apply α/β/byte order to all {props.matchingCount} rounds
      </ActionButton>
    </div>
  </Show>
);

// ─── Serpent step blocks ─────────────────────────────────────────────────

// Serpent key-expansion: three scalars (keyAuxName, outputPrefix,
// keyByteLength). All structural — editing them by hand breaks the spec.
// No S-box param to expose here (Serpent's S-boxes live on the per-round
// sub-bytes leaves, not on the schedule itself — unlike AES, which has
// the S-box on its schedule because the schedule consumes it for SubWord).
const SerpentKeyExpansionBlock = (props: BlockProps) => {
  const params = (): {
    keyAuxName?: string;
    outputPrefix?: string;
    keyByteLength?: number;
  } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Input aux</dt>
        <dd>{params().keyAuxName ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Output prefix</dt>
        <dd>{params().outputPrefix ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Key bytes</dt>
        <dd>{params().keyByteLength ?? "—"}</dd>
      </div>
    </dl>
  );
};

// Serpent bit-permutation: 128-entry table param. Editing the table by
// hand is impractical; we show the label (IP / FP) as a scalar and tuck
// the table behind a <details>. Display is a 16x8 grid of source-bit
// indices (matches the layout the constants file uses for line-by-line
// auditing). Read-only — this is a structural cipher constant.
const SerpentBitPermutationBlock = (props: BlockProps) => {
  const params = (): { table?: number[]; label?: string } => props.step.params as never;
  const table = (): readonly number[] => params().table ?? [];

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Permutation</dt>
          <dd>{params().label ?? "—"}</dd>
        </div>
      </dl>
      <details class="param-section param-collapsible">
        <summary class="param-section-label">
          Bit permutation table (128 entries — click to expand)
        </summary>
        <div class="serpent-bit-table">
          <For each={table()}>
            {(value, i) => (
              <span class="bit-table-cell" title={`output bit ${i()} ← input bit ${value}`}>
                {value}
              </span>
            )}
          </For>
        </div>
      </details>
    </>
  );
};

// Serpent add-round-key: one scalar (roundKeyAux). Same shape as AES
// AddRoundKeyBlock — no ApplyAllRow because each leaf intentionally
// points at a different round key.
const SerpentAddRoundKeyBlock = (props: BlockProps) => {
  const params = (): { roundKeyAux?: string } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Round key aux</dt>
        <dd>{params().roundKeyAux ?? "—"}</dd>
      </div>
    </dl>
  );
};

// Blowfish key schedule: the opaque 521-self-encryption monolith. One
// read-only scalar (outputPrefix) — the aux namespace it publishes the derived
// P-array + S-boxes under. Read-only because editing the prefix would break the
// round bodies' aux wiring; the 521-loop itself has no editable parameter.
const BlowfishKeyScheduleBlock = (props: { step: StepLeaf }) => {
  const params = (): { outputPrefix?: string } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Aux prefix</dt>
        <dd>{params().outputPrefix ?? "blowfish"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Operation</dt>
        <dd>521 self-encryptions → P[0..17] + S0..S3 (key-derived)</dd>
      </div>
    </dl>
  );
};

// Blowfish S-box lookup: the F function's aux-fed 32-bit word lookup. One
// read-only scalar (sboxName) — which of the four key-derived S-boxes this
// lookup reads. Read-only because the F function's four leaves each reference a
// distinct S-box (S0..S3); editing would corrupt the round.
const BlowfishSboxLookupBlock = (props: { step: StepLeaf }) => {
  const params = (): { sboxName?: string } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>S-box aux</dt>
        <dd>{params().sboxName ?? "—"}</dd>
      </div>
    </dl>
  );
};

// Twofish h-expand: the opaque half of the key schedule (RS S-vector +
// key-dependent S-box construction + 40 h evaluations). One read-only scalar
// (outputPrefix) — the aux namespace it publishes A/B + the four S-boxes under.
// Read-only because editing it would break the PHT blocks' + rounds' aux wiring;
// the h-function machinery itself has no editable parameter.
const TwofishHExpandBlock = (props: { step: StepLeaf }) => {
  const params = (): { outputPrefix?: string } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Aux prefix</dt>
        <dd>{params().outputPrefix ?? "twofish"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Operation</dt>
        <dd>RS S-vector → key-dependent S0..S3 + 40 h evals → A/B intermediates</dd>
      </div>
    </dl>
  );
};

// Twofish S-box lookup: the g function's aux-fed byte→byte substitution. One
// read-only scalar (sboxName) — which of the four key-derived S-boxes this
// lookup reads. Read-only because g's four leaves each reference a distinct
// S-box (S0..S3); editing would corrupt the round.
const TwofishSboxLookupBlock = (props: { step: StepLeaf }) => {
  const params = (): { sboxName?: string } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>S-box aux</dt>
        <dd>{params().sboxName ?? "—"}</dd>
      </div>
    </dl>
  );
};

// Twofish publish-subkeys: the aux-publish tail of the visible PHT half. One
// read-only scalar (outputPrefix) — the aux namespace the 40 subkeys are stored
// under for the rounds + whitening. Read-only because editing it would orphan
// the round consumers' aux reads.
const TwofishPublishSubkeysBlock = (props: { step: StepLeaf }) => {
  const params = (): { outputPrefix?: string } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Aux prefix</dt>
        <dd>{params().outputPrefix ?? "twofish"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Operation</dt>
        <dd>Publish K[0..39] → aux for input/output whitening + the 16 rounds</dd>
      </div>
    </dl>
  );
};

// Serpent SubBytes: 16-entry 4-bit S-box. Rendered as an editable 4x4
// grid (16 cells in row-major order, index 0 top-left). Each cell is a
// ByteCellInput; the user can experiment by swapping values, and the
// effect propagates through the spec store like any other param edit.
//
// sboxIndex (0..7) is shown read-only as context — telling the user
// "this is S-box 3 of the 8 Serpent S-boxes" so they can correlate
// with the cipher description.
//
// Same validation suite as the AES SboxEditor — `findDuplicateIndices`,
// `countRedundantDuplicates`, `repairToPermutation`, and `invertSbox` are
// all size-parameterized by `values.length`, so they work at N=16 without
// modification. The visual presentation differs (warning banner is
// tighter to match the smaller grid; cross-mode Sync names the specific
// S-box index because Serpent cycles 8 distinct tables across the 32
// rounds — see `syncSboxInverseToCounterpartByIndex` in
// `stores/spec.ts`).
const SerpentSubBytesBlock = (props: BlockProps) => {
  const params = (): { sbox?: number[]; sboxIndex?: number } => props.step.params as never;
  const sbox = (): readonly number[] => params().sbox ?? [];
  const sboxIndex = (): number => params().sboxIndex ?? 0;

  // Memoize per-cell validation so the 16 ByteCellInputs below don't
  // each recompute the dup-set on every render. Mirrors SboxEditor's
  // pattern at N=256.
  const duplicateSet = createMemo(() => findDuplicateIndices(sbox()));
  const collisionGroups = createMemo(() => collisionGroupsByIndex(sbox()));
  const redundantCount = createMemo(() => countRedundantDuplicates(sbox()));
  const isBijective = (): boolean => redundantCount() === 0;

  const writeSbox = (next: number[]) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      sbox: next,
    });
  };

  const handleRepair = () => {
    writeSbox(repairToPermutation(sbox()));
  };

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>S-box index</dt>
          <dd>S_{params().sboxIndex ?? "—"}</dd>
        </div>
      </dl>
      <Show when={redundantCount() > 0}>
        {/* Warning banner — same red-leaning visual language as
            SboxEditor's, scoped to a tighter padding class so it sits
            comfortably above a 4×4 grid instead of a 16×16 one. */}
        <div class="serpent-sbox-warning-banner" role="alert">
          <span class="sbox-warning-icon" aria-hidden="true">
            ⚠
          </span>
          <span class="sbox-warning-text">
            This 4-bit S-box must be a permutation of 0–15 (each value appears exactly once). With{" "}
            {redundantCount()} duplicate {redundantCount() === 1 ? "value" : "values"}, the table is
            not invertible.
          </span>
          <ActionButton
            class="sbox-warning-repair"
            onAction={handleRepair}
            feedbackLabel={`Repaired Serpent S_${sboxIndex()} to a permutation`}
          >
            Repair to permutation
          </ActionButton>
        </div>
      </Show>
      <div class="param-section">
        <div class="param-section-label">S-box (16 entries, 4-bit each)</div>
        <div class="serpent-sbox-grid">
          <For each={sbox()}>
            {(value, i) => (
              <div
                class="serpent-sbox-cell-wrap"
                title={
                  collisionGroups().get(i())
                    ? `S[${i()}] = ${value} — duplicate value (also at ${(
                        collisionGroups().get(i()) ?? []
                      )
                        .filter((j) => j !== i())
                        .map((j) => `S[${j}]`)
                        .join(", ")})`
                    : `S[${i()}] = ${value}`
                }
              >
                <ByteCellInput
                  compact
                  value={value}
                  duplicate={duplicateSet().has(i())}
                  onCommit={(next) => {
                    // Clamp to 0..15 — anything outside that range isn't a
                    // valid 4-bit S-box entry. ByteCellInput will already
                    // refuse non-byte values; we tighten further here.
                    const clamped = Math.max(0, Math.min(15, next));
                    const out = [...sbox()];
                    out[i()] = clamped;
                    writeSbox(out);
                  }}
                />
              </div>
            )}
          </For>
        </div>
      </div>
      <SerpentSyncInverseRow
        currentSbox={sbox()}
        sboxIndex={sboxIndex()}
        stepType={props.step.type}
        isBijective={isBijective()}
      />
    </>
  );
};

// Cross-mode mirror for Serpent SubBytes. Distinct from the AES
// `SyncInverseRow` because Serpent cycles **8 different S-boxes** across
// its 32 rounds — broadcasting one inverted table to every
// `serpent.sub-bytes@1` leaf in the counterpart slot would overwrite 28
// of the 32 rounds with the wrong inverse. The button (and its mutator)
// filter by `sboxIndex` so editing S_3 in encrypt and clicking Sync only
// updates the decrypt-side leaves whose `sboxIndex === 3`.
//
// Label names the specific S-box ("Sync inverse S_3 to decrypt") — the
// pedagogical hook. Tooltip explicitly states the other 7 are
// independent so users don't think the button is broken when their S_5
// edits stay un-mirrored.
const SerpentSyncInverseRow = (props: {
  currentSbox: readonly number[];
  sboxIndex: number;
  stepType: string;
  isBijective: boolean;
}) => {
  const mode = useMode();
  const counterpartLabel = (): string => (mode() === "encrypt" ? "decrypt" : "encrypt");
  const buttonLabel = (): string => `Sync inverse S_${props.sboxIndex} to ${counterpartLabel()}`;
  const disabledTooltip =
    "Repair to a permutation first — the inverse is undefined for a non-bijective table.";
  const enabledTooltip = (): string =>
    `Compute the inverse of this S-box (S_${props.sboxIndex}) and write it to every ${props.stepType} step in the ${counterpartLabel()} slot whose sboxIndex is ${props.sboxIndex}. The other 7 Serpent S-boxes are independent — Sync each separately when you edit it.`;

  return (
    <div class="sync-inverse-row">
      <ActionButton
        disabled={!props.isBijective}
        title={props.isBijective ? enabledTooltip() : disabledTooltip}
        feedbackLabel={`Synced inverse S_${props.sboxIndex} to ${counterpartLabel()} mode`}
        // Surface mirror class for the cross-mode-mirror-coverage test —
        // same rationale as the AES SyncInverseRow above.
        data-mirror-class="inverse"
        onAction={() => {
          if (!props.isBijective) return; // belt-and-braces; button is disabled
          const inverted = invertSbox(props.currentSbox);
          syncSboxInverseToCounterpartByIndex(props.stepType, props.sboxIndex, inverted);
        }}
      >
        {buttonLabel()}
      </ActionButton>
    </div>
  );
};

// Empty-params placeholder for steps whose entire computation is in code
// (the Serpent LT and inverse LT). Avoids the raw-JSON fallback rendering
// `{}` for an empty params object.
const NoParamsBlock = (props: { label: string }) => <div class="muted small">{props.label}</div>;

// Aux-publish tail of the DECOMPOSED AES key schedule
// (key-schedule-decomposition K1a). Read-only: both params are structural —
// `outputPrefix` must match what the AddRoundKey consumers read, and `rounds`
// must match the schedule the builder emitted. Editing either would desync the
// producer from the consumers, so we surface them as a labelled scalar header
// (same posture as the read-only DES permutation blocks) rather than inputs.
const PublishRoundKeysBlock = (props: { step: StepLeaf }) => {
  const params = (): { outputPrefix?: string; rounds?: number } => props.step.params as never;
  const rounds = (): number => params().rounds ?? 0;
  const prefix = (): string => params().outputPrefix ?? "roundKey";
  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Aux prefix (write)</dt>
          <dd>{prefix()}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Round keys</dt>
          <dd>
            {rounds() + 1} keys ({prefix()}.0 … {prefix()}.{rounds()})
          </dd>
        </div>
      </dl>
      <p class="muted small">
        Writes the derived round keys into the aux map for the AddRoundKey steps. The interesting
        math is the recurrence leaves above this tail; these params are structural and not meant to
        be edited.
      </p>
    </>
  );
};

// ─── Serpent key-schedule decomposition blocks (K3a) ──────────────────────
//
// The decomposed Serpent key schedule introduces two leaf step types beyond
// the shared port-native primitives:
//   - `serpent.publish-round-keys@1` — the B-minimal aux-publish tail. Uses a
//     `count` param (fixed 33), distinct from AES/Speck's `rounds`, so it gets
//     its own read-only block rather than reusing PublishRoundKeysBlock.
//   - `serpent.key-sbox@1` — the per-round-key bitsliced S-box + IP. Single
//     `sboxIndex` param; read-only (the builder derives it as (35-i) mod 8).

const SerpentPublishRoundKeysBlock = (props: { step: StepLeaf }) => {
  const params = (): { outputPrefix?: string; count?: number } => props.step.params as never;
  const count = (): number => params().count ?? 33;
  const prefix = (): string => params().outputPrefix ?? "roundKey";
  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Aux prefix (write)</dt>
          <dd>{prefix()}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Round keys</dt>
          <dd>
            {count()} keys ({prefix()}.0 … {prefix()}.{count() - 1})
          </dd>
        </div>
      </dl>
      <p class="muted small">
        Writes the 33 derived Serpent round keys into the aux map for the AddRoundKey steps. The
        interesting math is the recurrence + per-group S-box/IP leaves above this tail; these params
        are structural and not meant to be edited.
      </p>
    </>
  );
};

const SerpentKeySboxBlock = (props: { step: StepLeaf }) => {
  const params = (): { sboxIndex?: number } => props.step.params as never;
  const sboxIndex = (): number => params().sboxIndex ?? 0;
  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>S-box</dt>
          <dd>S{sboxIndex()}</dd>
        </div>
      </dl>
      <p class="muted small">
        Applies the bitsliced forward Serpent S-box S{sboxIndex()} to one group of four prekey
        words, then the Initial Permutation, producing one 16-byte round key. The S-box index walks
        down the table with wraparound (group i uses S₍₃₅₋ᵢ₎ ₘₒ𝒹 ₈); it is derived structurally by
        the key-schedule builder, not edited here.
      </p>
    </>
  );
};

// ─── DES step blocks (Phase 4 of docs/plans/des-feistel.md) ───────────────
//
// All seven DES step types ship structural FIPS-46-3 tables that the user
// CAN edit pedagogically (swap IP for an identity, replace S1 with a "weak"
// table) but won't typically need to. The blocks below render the tables
// read-only — same pattern as Serpent's bit-permutation block — with a
// scalar header showing which permutation / round key the leaf consumes.
//
// No ApplyAllRow on any DES block: every IP/FP/E/P/S-box step type appears
// either zero times (key-schedule, IP/FP) or sixteen times (the per-round
// F internals), and the per-round xor-with-K leaves intentionally reference
// DIFFERENT round keys. Copying one step's params to every match would
// either be a no-op or actively break the cipher (every round XOR'd with
// K_1 wouldn't decrypt).

// Generic table block — reused by IP/FP/E/P. Single param: `table: number[]`.
// Shown as a labelled scalar (per the doc's `name` field, looked up via the
// registry would be ideal but we hardcode per step type below since this
// component is itself the lookup) plus a collapsed grid of source-bit
// indices. The grid uses 16-wide rows so the FIPS tables display close to
// the layout used in the constants file.
const DesPermutationBlock = (props: { step: StepLeaf }) => {
  const params = (): { table?: number[] } => props.step.params as never;
  const table = (): readonly number[] => params().table ?? [];
  const stepLabel = (): string => {
    switch (props.step.type) {
      case "des.initial-permutation@1":
        return "Initial Permutation (IP)";
      case "des.final-permutation@1":
        return "Final Permutation (FP = IP⁻¹)";
      case "des.expand-R@1":
        return "Expansion (E)";
      case "des.p-permutation@1":
        return "P permutation";
      case "des.bit-permute@1":
        // Serves both PC-1 (56) and PC-2 (48); the "Output bits" row below
        // (table().length) tells them apart.
        return "Permuted Choice (PC-1 / PC-2)";
      default:
        return props.step.type;
    }
  };

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Permutation</dt>
          <dd>{stepLabel()}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Output bits</dt>
          <dd>{table().length}</dd>
        </div>
      </dl>
      <details class="param-section param-collapsible">
        <summary class="param-section-label">
          Source-bit table ({table().length} entries — click to expand)
        </summary>
        {/* Reuses the serpent-bit-table CSS class for the grid layout —
            same visual rhythm as Serpent's IP/FP table view. Each cell is
            the 1-indexed FIPS source-bit number for the output at that
            position. */}
        <div class="serpent-bit-table">
          <For each={table()}>
            {(value, i) => (
              <span class="bit-table-cell" title={`output bit ${i() + 1} ← input bit ${value}`}>
                {value}
              </span>
            )}
          </For>
        </div>
      </details>
    </>
  );
};

// DES key-schedule decomposition (K4a) — the C/D half-rotation. Thin
// read-only view of the shift amount; the half-width is structural (28).
// No ApplyAllRow: the 16 rotate leaves use DIFFERENT shifts (the FIPS
// schedule), so copying one to all would break the cipher.
const DesRotateHalvesBlock = (props: { step: StepLeaf }) => {
  const params = (): { shift?: number; halfBits?: number } => props.step.params as never;
  const shift = (): number => params().shift ?? 0;
  const halfBits = (): number => params().halfBits ?? 28;
  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Left-rotate by</dt>
          <dd>
            {shift()} bit{shift() === 1 ? "" : "s"}
          </dd>
        </div>
        <div class="param-scalar-row">
          <dt>Half width</dt>
          <dd>{halfBits()} bits (C and D)</dd>
        </div>
      </dl>
      <p class="muted small">
        Left-rotates both {halfBits()}-bit halves (C and D) of the key register by {shift()} bit
        {shift() === 1 ? "" : "s"}. The per-round shift amount comes from the FIPS 46-3 schedule (1
        or 2); it is structural and not meant to be edited.
      </p>
    </>
  );
};

// DES key-schedule decomposition (K4a) — the aux-publish tail. Thin read-only
// view (parallel to SerpentPublishRoundKeysBlock). DES emits a fixed 16 round
// keys (no key-size variant).
const DesPublishRoundKeysBlock = (props: { step: StepLeaf }) => {
  const params = (): { outputPrefix?: string; count?: number } => props.step.params as never;
  const count = (): number => params().count ?? 16;
  const prefix = (): string => params().outputPrefix ?? "roundKey";
  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Aux prefix (write)</dt>
          <dd>{prefix()}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Round keys</dt>
          <dd>
            {count()} keys ({prefix()}.0 … {prefix()}.{count() - 1})
          </dd>
        </div>
      </dl>
      <p class="muted small">
        Writes the 16 derived DES round keys into the aux map for the per-round key-mixing steps.
        The interesting math is the PC-1 / rotate / PC-2 leaves above this tail; these params are
        structural and not meant to be edited.
      </p>
    </>
  );
};

// rsa.publish-key-params@1 — the aux-publish tail of the RSA "Key Generation"
// group (RSA Phase 2). Read-only structural view (parallel to the
// publish-round-keys blocks). RSA's exports are NAMED (n / e / d), not indexed.
// Each direction publishes exactly the key its ladder uses — the public key
// {n, e} on encrypt, the private key {n, d} on decrypt — so the rows are
// derived from `params.keys`, not hardcoded.
const RsaPublishKeyParamsBlock = (props: { step: StepLeaf }) => {
  const params = (): { outputPrefix?: string; keys?: readonly string[] } =>
    props.step.params as never;
  const prefix = (): string => params().outputPrefix ?? "rsa";
  const keys = (): readonly string[] => params().keys ?? [];
  // The private exponent d marks the private key; otherwise it's the public key.
  const keyKind = (): string => (keys().includes("d") ? "Private key" : "Public key");
  const published = (): string =>
    keys()
      .map((k) => `${prefix()}.${k}`)
      .join(", ");
  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Aux prefix (write)</dt>
          <dd>{prefix()}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>{keyKind()} (published)</dt>
          <dd>{published()}</dd>
        </div>
      </dl>
      <p class="muted small">
        Writes this direction's key material into the aux map so the exponentiation ladder can read
        it across the Key-Generation group boundary. Encryption exports the public key (n, e);
        decryption the private key (n, d) — each tail publishes exactly the key it uses, so nothing
        is written-but-unread. The interesting math is the n = p·q / φ = (p−1)(q−1) / d = e⁻¹ mod φ
        leaves above this tail; these params are structural.
      </p>
    </>
  );
};

// DES key-schedule: three structural tables (PC-1, PC-2, SHIFTS) plus two
// aux-name scalars. Rendered the same way as the AES key-expansion block
// (scalars + collapsible table) but with three independent tables instead
// of one S-box. Retained for the monolithic `des.key-schedule@1` (KAT oracle
// + pre-K4 saved docs); shipped DES specs now use the decomposed builder.
const DesKeyScheduleBlock = (props: { step: StepLeaf }) => {
  const params = (): {
    keyAuxName?: string;
    outputPrefix?: string;
    pc1?: readonly number[];
    pc2?: readonly number[];
    shifts?: readonly number[];
  } => props.step.params as never;
  const pc1 = (): readonly number[] => params().pc1 ?? [];
  const pc2 = (): readonly number[] => params().pc2 ?? [];
  const shifts = (): readonly number[] => params().shifts ?? [];

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Input aux</dt>
          <dd>{params().keyAuxName ?? "—"}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Output prefix</dt>
          <dd>{params().outputPrefix ?? "—"}</dd>
        </div>
      </dl>
      <details class="param-section param-collapsible">
        <summary class="param-section-label">
          PC-1 (Permuted Choice 1, 56 entries — drops parity bits)
        </summary>
        <div class="serpent-bit-table">
          <For each={pc1()}>
            {(value, i) => (
              <span class="bit-table-cell" title={`output bit ${i() + 1} ← input bit ${value}`}>
                {value}
              </span>
            )}
          </For>
        </div>
      </details>
      <details class="param-section param-collapsible">
        <summary class="param-section-label">
          PC-2 (Permuted Choice 2, 48 entries — selects K_i from C_i ‖ D_i)
        </summary>
        <div class="serpent-bit-table">
          <For each={pc2()}>
            {(value, i) => (
              <span class="bit-table-cell" title={`output bit ${i() + 1} ← input bit ${value}`}>
                {value}
              </span>
            )}
          </For>
        </div>
      </details>
      <details class="param-section param-collapsible">
        <summary class="param-section-label">
          Per-round left shifts (16 entries — cumulative total 28)
        </summary>
        <div class="serpent-bit-table">
          <For each={shifts()}>
            {(value, i) => (
              <span
                class="bit-table-cell"
                title={`round ${i() + 1}: shift halves left by ${value}`}
              >
                {value}
              </span>
            )}
          </For>
        </div>
      </details>
    </>
  );
};

// xor-with-K: one scalar (roundKeyAux). Same shape as AES AddRoundKey's
// block — no ApplyAllRow because each leaf intentionally references a
// different round key (roundKey.0 … roundKey.15 for encrypt; reversed
// order for decrypt).
const DesXorWithKBlock = (props: { step: StepLeaf }) => {
  const params = (): { roundKeyAux?: string } => props.step.params as never;
  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Round key aux</dt>
        <dd>{params().roundKeyAux ?? "—"}</dd>
      </div>
    </dl>
  );
};

// DES S-boxes: 8 distinct 6→4 substitution tables (S1..S8). Each is a
// 4-row × 16-column grid; this is a brand-new UI pattern in the editor
// (Serpent has one S-box per leaf indexed by `sboxIndex`, but DES carries
// all 8 as `params.sboxes[8][4][16]` on a single leaf).
//
// Each S-box hides behind its own collapsed `<details>` so the editor
// isn't 512 visible cells on first render. Cells ARE editable (Phase 6e):
// the pedagogical "experiment with weak S-boxes" use case is exactly
// what the editor exists for, and AES SubBytes is editable on the same
// principle. Each row must be a permutation of 0..15 — `findDuplicateIndices`
// (size-parameterized on `values.length`) flags collisions per row;
// `repairToPermutation` would compose only over a single row, but we
// surface duplicates inline rather than offering a repair button because
// the FIPS 46-3 tables ARE the canonical state and the user can always
// hit "Reset spec" to recover.
//
// Why no ApplyAllRow here: this step type appears exactly once per spec
// (the F-function's s-boxes leaf is a single node carrying all 8 tables
// at once). "Apply this S-box to all matching steps" would be a no-op.
const DesSBoxesBlock = (props: { step: StepLeaf }) => {
  const params = (): { sboxes?: readonly (readonly (readonly number[])[])[] } =>
    props.step.params as never;
  const sboxes = (): readonly (readonly (readonly number[])[])[] => params().sboxes ?? [];

  // Pre-compute every row's duplicate-set in a single memoized walk so the
  // per-row check inside the nested For loops below is a Map lookup (no
  // per-cell allocation). Hoisting to the component level follows the
  // project's pattern (`SerpentSubBytesBlock`) — `For` callbacks aren't
  // reactive scopes, so a `createMemo` defined inside one wouldn't fire
  // correctly when sboxes() updates after an edit. CLAUDE.md gotcha,
  // codified.
  const dupesByRow = createMemo(() =>
    sboxes().map((box) => box.map((row) => findDuplicateIndices(row))),
  );

  // Commit a single-cell edit. Deep-clones the sboxes tensor down to the
  // affected row so reference-equality is preserved on the untouched
  // boxes / rows (the rest of `editStepParams`'s short-circuit logic
  // expects that). Value is clamped to 0..15 because DES S-boxes hold
  // 4-bit outputs; ByteCellInput already refuses non-byte input but we
  // tighten further here.
  const writeCell = (boxIdx: number, rowIdx: number, colIdx: number, next: number): void => {
    const clamped = Math.max(0, Math.min(15, next));
    const current = sboxes();
    // Build mutable arrays (number[][][]) so the result satisfies the
    // Json branch of `editStepParams`'s param type. The `readonly` chain
    // on `current` doesn't propagate through .map(), so each level needs
    // an explicit copy.
    const nextBoxes: number[][][] = current.map((box, bi) =>
      bi !== boxIdx
        ? box.map((row) => [...row])
        : box.map((row, ri) => {
            if (ri !== rowIdx) return [...row];
            const nextRow = [...row];
            nextRow[colIdx] = clamped;
            return nextRow;
          }),
    );
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      sboxes: nextBoxes,
    });
  };

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>S-box count</dt>
          <dd>{sboxes().length}</dd>
        </div>
      </dl>
      {/* <Index> instead of <For> so the eight <details> DOM nodes
          reconcile by position rather than reference equality. A single
          cell edit produces a new sboxes() array whose 8 entries all
          have new references (writeCell deep-clones every box's rows
          to keep editStepParams' short-circuit logic happy), so <For>
          would re-mount all 8 <details> and collapse the user's open
          disclosure. <Index> keeps the <details> nodes mounted; only
          the inner cells re-render. UX-B from DES Phase 6e partial
          walk #2 (2026-05-22). */}
      <Index each={sboxes()}>
        {(box, idx) => (
          <details class="param-section param-collapsible">
            <summary class="param-section-label">
              S{idx + 1} (4 rows × 16 cols, 4-bit values — click to expand)
            </summary>
            {/* Each row is its own 16-col grid. ByteCellInput cells use
                the existing compact mode (same one Serpent's 4×4 S-box
                grid uses) so the visual rhythm stays consistent across
                the editor surfaces. Per-row duplicate detection: each
                row must be a permutation of 0..15, and `findDuplicateIndices`
                is size-parameterized on `values.length` so it works
                unchanged at N=16. */}
            <div class="des-sbox-table">
              <For each={box()}>
                {(row, r) => (
                  <div class="des-sbox-row" data-row={r()}>
                    <For each={row}>
                      {(value, c) => (
                        <ByteCellInput
                          compact
                          value={value}
                          duplicate={dupesByRow()[idx]?.[r()]?.has(c()) ?? false}
                          title={
                            dupesByRow()[idx]?.[r()]?.has(c())
                              ? `S${idx + 1}[row ${r()}][col ${c()}] = ${value} — duplicate value in this row (each row must be a permutation of 0..15)`
                              : `S${idx + 1}[row ${r()}][col ${c()}] = ${value}`
                          }
                          onCommit={(next) => writeCell(idx, r(), c(), next)}
                        />
                      )}
                    </For>
                  </div>
                )}
              </For>
            </div>
          </details>
        )}
      </Index>
    </>
  );
};

// ─── Slice 10 aux primitives ─────────────────────────────────────────────
//
// These three step types arrive on the canvas via palette drop with empty
// params, so unlike the structural read-only blocks above (KeyExpansion,
// SpeckKeySchedule, AddRoundKey), they MUST be editable in place —
// otherwise the user can't fill in the aux names and the step never runs.
//
// No ApplyAllRow on any of them: every aux-load/aux-xor/aux-copy leaf is
// expected to point at distinct aux keys by design (the whole point of the
// primitives is wiring DIFFERENT slots together). Copying one step's
// params onto every sibling would silently route all of them at the same
// slot and produce wrong output — same reasoning as AddRoundKeyBlock.

// Generic editable text-input row used by the aux-primitive blocks. Keeps
// the per-block bodies tight and the input styling consistent with the
// `.param-scalar-row` look of the read-only blocks above.
const AuxNameInput = (props: {
  value: string;
  placeholder: string;
  onCommit: (v: string) => void;
}) => {
  const [draft, setDraft] = createSignal(props.value);
  // Re-sync the local draft if the upstream value changes (e.g. another
  // tab edits the spec, or an Apply-to-all on a different step type lands).
  let lastUpstream = props.value;
  const syncedDraft = () => {
    if (props.value !== lastUpstream) {
      lastUpstream = props.value;
      setDraft(props.value);
    }
    return draft();
  };
  const commit = () => {
    const next = draft().trim();
    if (next !== props.value) props.onCommit(next);
    // Snap draft to the committed value (or upstream if commit was a no-op).
    setDraft(next || props.value);
  };
  return (
    <input
      type="text"
      class="aux-name-input"
      spellcheck={false}
      placeholder={props.placeholder}
      value={syncedDraft()}
      onInput={(e) => setDraft(e.currentTarget.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          commit();
          e.currentTarget.blur();
        } else if (e.key === "Escape") {
          setDraft(props.value);
          e.currentTarget.blur();
        }
      }}
    />
  );
};

// aux-load: { auxName: string, value: number[] }.
// Renders an editable text input for the destination aux key + a horizontal
// row of ByteCellInput byte cells for `value` (reuses the `.rcon-row`
// styling from KeyExpansionBlock). Append/remove buttons let the user
// grow/shrink the byte sequence — palette inserts start at length 0 and
// the user adds bytes one at a time.
//
// Pedagogical note: aux-load is one of the first step types a user touches
// when wiring a new chaining mode (CBC's IV, CTR's counter start, OFB's
// keystream seed). Reaching it via the palette gives no prior context for
// what bytes the row is asking for, so we render an inline `.muted small`
// hint beneath the byte cells listing the common shapes (16-byte IV,
// 16-byte counter, mode constant). Cheap copy is the difference between
// "user can keep going" and "user backs out of the step entirely."
const AuxLoadBlock = (props: { step: StepLeaf }) => {
  const params = (): { auxName?: string; value?: readonly number[] } => props.step.params as never;
  const auxName = () => params().auxName ?? "";
  const value = (): readonly number[] => params().value ?? [];

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Aux name (write)</dt>
          <dd>
            <AuxNameInput
              value={auxName()}
              placeholder="e.g. iv, counter, tweak"
              onCommit={(v) => writeParams({ auxName: v })}
            />
          </dd>
        </div>
      </dl>
      <div class="param-section">
        {/* Label restates which aux slot the bytes land in (the aux name
            edited above) so the row reads as "this is what gets published
            under that key" — read top-to-bottom the connection is obvious
            without scanning back up. The byte count tail (`N total`) is a
            running counter the user can match against the placeholder
            hint below. */}
        <div class="param-section-label">
          Bytes published under aux[{auxName() || "name"}] ({value().length} total)
        </div>
        <div class="rcon-row">
          <For each={value()}>
            {(byte, i) => (
              <ByteCellInput
                value={byte}
                onCommit={(next) => {
                  const out = [...value()];
                  out[i()] = next;
                  writeParams({ value: out });
                }}
              />
            )}
          </For>
        </div>
        {/* Why this hint exists: users reaching this step via palette drop
            have no prior context for what bytes belong here. The three
            canonical shapes (CBC IV, CTR counter start, per-mode constant)
            cover essentially every aux-load instance the shipped specs
            need, and naming them by use case rather than by byte count
            lets the user reason "I want an IV" → "16 bytes." */}
        <div class="muted small aux-byte-hint">
          The byte sequence published under <code>aux[{auxName() || "name"}]</code>. Common uses: 16
          bytes for an IV, 16 bytes for a counter starting value, a per-mode constant.
        </div>
        <div class="aux-byte-controls">
          <button
            type="button"
            onClick={() => writeParams({ value: [...value(), 0] })}
            title="Append a zero byte to the value"
          >
            + byte
          </button>
          <button
            type="button"
            onClick={() => {
              const v = value();
              if (v.length > 0) writeParams({ value: v.slice(0, -1) });
            }}
            disabled={value().length === 0}
            title="Drop the last byte"
          >
            − byte
          </button>
        </div>
      </div>
    </>
  );
};

// aux-xor: { from: string, into: string }.
// Two editable aux-name inputs. The graceful-on-missing semantic is in the
// executor — leaving either field empty just produces an orphaned-read
// warning glyph in the graph view rather than throwing.
const AuxXorBlock = (props: { step: StepLeaf }) => {
  const params = (): { from?: string; into?: string } => props.step.params as never;

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>From (read)</dt>
        <dd>
          <AuxNameInput
            value={params().from ?? ""}
            placeholder="aux key to XOR IN"
            onCommit={(v) => writeParams({ from: v })}
          />
        </dd>
      </div>
      <div class="param-scalar-row">
        <dt>Into (read+write)</dt>
        <dd>
          <AuxNameInput
            value={params().into ?? ""}
            placeholder="aux key to accumulate into"
            onCommit={(v) => writeParams({ into: v })}
          />
        </dd>
      </div>
    </dl>
  );
};

// aux-copy: { from: string, to: string }. Mirror of AuxXorBlock with the
// destination key labelled `to` to match the executor's params.
const AuxCopyBlock = (props: { step: StepLeaf }) => {
  const params = (): { from?: string; to?: string } => props.step.params as never;

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>From (read)</dt>
        <dd>
          <AuxNameInput
            value={params().from ?? ""}
            placeholder="aux key to copy FROM"
            onCommit={(v) => writeParams({ from: v })}
          />
        </dd>
      </div>
      <div class="param-scalar-row">
        <dt>To (write)</dt>
        <dd>
          <AuxNameInput
            value={params().to ?? ""}
            placeholder="aux key to copy TO"
            onCommit={(v) => writeParams({ to: v })}
          />
        </dd>
      </div>
    </dl>
  );
};

// ─── Phase-2 chaining-mode primitives ─────────────────────────────────────
//
// Three blocks for the iv-load / xor-aux-into-state / state-to-aux step
// types that compose into CBC's per-block chaining math. Same authoring
// model as the Slice 10 aux primitives: every leaf is expected to point
// at distinct slots, so no ApplyAllRow. The graceful missing-aux semantic
// is in the executors — leaving a field empty produces an orange `!`
// glyph on the graph node, not a runtime throw.

// iv-load: { ivAuxName: string, outAuxName: string }. Bytes-in-aux to
// matrix-in-aux bridge, used once before the iterate loop in CBC/OFB/CFB
// specs. The labels distinguish the source (typically `iv`, seeded by the
// App from the IvInput field) from the destination (typically `chain`).
const IvLoadBlock = (props: { step: StepLeaf }) => {
  const params = (): { ivAuxName?: string; outAuxName?: string } => props.step.params as never;

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>IV aux (read, Uint8Array 16)</dt>
        <dd>
          <AuxNameInput
            value={params().ivAuxName ?? ""}
            placeholder="aux key holding 16 IV bytes — typically iv"
            onCommit={(v) => writeParams({ ivAuxName: v })}
          />
        </dd>
      </div>
      <div class="param-scalar-row">
        <dt>Output aux (write, MatrixState)</dt>
        <dd>
          <AuxNameInput
            value={params().outAuxName ?? ""}
            placeholder="aux key to publish matrix — typically chain"
            onCommit={(v) => writeParams({ outAuxName: v })}
          />
        </dd>
      </div>
    </dl>
  );
};

// xor-aux-into-state: { auxName: string }. The chaining XOR — state ⊕=
// aux[name]. One slot only (the operand); the state side is implicit.
const XorAuxIntoStateBlock = (props: { step: StepLeaf }) => {
  const params = (): { auxName?: string } => props.step.params as never;

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Aux (read, MatrixState)</dt>
        <dd>
          <AuxNameInput
            value={params().auxName ?? ""}
            placeholder="aux key to XOR INTO state — typically chain"
            onCommit={(v) => writeParams({ auxName: v })}
          />
        </dd>
      </div>
    </dl>
  );
};

// state-to-aux: { auxName: string }. Snapshot the running state into an
// aux slot. Mirror of XorAuxIntoStateBlock — single slot, no orphan
// reads (the step has no aux inputs).
const StateToAuxBlock = (props: { step: StepLeaf }) => {
  const params = (): { auxName?: string } => props.step.params as never;

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Aux (write)</dt>
        <dd>
          <AuxNameInput
            value={params().auxName ?? ""}
            placeholder="aux key to snapshot state into"
            onCommit={(v) => writeParams({ auxName: v })}
          />
        </dd>
      </div>
    </dl>
  );
};

// ─── Port-native primitive blocks (Slice S1 of sha-256-density-polish) ───
//
// These editors fill the raw-JSON fallback gap that SHA-256 surfaced as the
// first reachable port-native cipher with ~1800 leaves. The editability rule
// follows existing precedent in this file (BlockSizeBlock, KeyExpansionBlock):
// **read-only when edit-without-rewire produces a runtime throw; editable
// when it produces wrong-but-defined output.**
//
//   - `bits` on rotate/shift, `offset`/`length` on byte-slice, `auxName` on
//     aux-load-bytes, `padByte`/`padTarget` on pad-with-byte:
//     editable. Editing produces a divergent trace + wrong digest, visible
//     in the KAT and via the running state — exactly the "tinker with the
//     cipher" pedagogy the project ships.
//   - `inputCount` on xor/and/add/concat, `widths` on split-bytes,
//     `byteLength` on aux-load-bytes, `sourceByteLength` on byte-slice,
//     `blockSize` on pad-with-byte, `bytes` on constant-load (large hex
//     dump):
//     read-only. Editing without re-wiring downstream consumers throws
//     "port not wired" at the next run; that's a poor pedagogical surface
//     (the user sees a hard error, not a divergent cipher).
//   - `wordBits` on rotate/shift: read-only because all shipped consumers
//     hard-code 32. Becomes editable when SHA-512 (which needs `wordBits:
//     64`) lands.
//
// No ApplyAllRow on most of these: port-native primitives recur ~hundreds of
// times in SHA-256 (e.g. 192 `rotate-bits-right@1` leaves across σ0/σ1/Σ0/Σ1),
// and "apply this rotation amount to all 192" would overwrite the FIPS-180-4
// constants. The exception is `pad-with-byte@1` (appears once per spec) and
// `rotate-bits-right@1` (appears 192 times in SHA-256, but the row is gated
// behind matchingCount > 1 anyway and the per-leaf bit count is the
// pedagogical knob).

/**
 * Small editable integer input for port-native primitive params (`bits`,
 * `offset`, `length`, `padTarget`). Mirrors `AuxNameInput`'s commit-on-blur /
 * Enter / Escape-to-reset pattern but typed as a number; clamps to
 * [min, max] and refuses non-integer or out-of-range input. Returns to the
 * upstream value when commit is a no-op or input is invalid.
 *
 * Why local helper not a shared component: only port-native primitives need
 * a generic integer input; AES/Speck/Serpent editors all use ByteCellInput
 * (which is 0..255 specifically) or read-only scalars. Hoisting to
 * `src/ui/components/` would over-generalize.
 */
const IntInput = (props: {
  value: number;
  min?: number;
  max?: number;
  placeholder?: string;
  onCommit: (v: number) => void;
}) => {
  const [draft, setDraft] = createSignal(String(props.value));
  // Re-sync the local draft if upstream value changes (Apply-to-all on a
  // different step, or another tab edits the spec).
  let lastUpstream = props.value;
  const syncedDraft = () => {
    if (props.value !== lastUpstream) {
      lastUpstream = props.value;
      setDraft(String(props.value));
    }
    return draft();
  };
  const commit = () => {
    const parsed = Number.parseInt(draft().trim(), 10);
    const valid =
      Number.isFinite(parsed) &&
      Number.isInteger(parsed) &&
      (props.min === undefined || parsed >= props.min) &&
      (props.max === undefined || parsed <= props.max);
    if (!valid) {
      setDraft(String(props.value));
      return;
    }
    if (parsed !== props.value) props.onCommit(parsed);
    setDraft(String(parsed));
  };
  return (
    <input
      type="text"
      class="int-input"
      inputmode="numeric"
      spellcheck={false}
      placeholder={props.placeholder ?? ""}
      value={syncedDraft()}
      onInput={(e) => setDraft(e.currentTarget.value)}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === "Enter") {
          commit();
          e.currentTarget.blur();
        } else if (e.key === "Escape") {
          setDraft(String(props.value));
          e.currentTarget.blur();
        }
      }}
    />
  );
};

// rotate-bits-right@1 / shift-bits-right@1.
//
// Editable `bits` (non-negative integer; rotate semantics modulo wordBits,
// shift semantics saturate to zero past wordBits). Read-only `wordBits`
// (every shipped SHA-256 leaf uses 32; SHA-512 will add 64). Operation
// labelled distinctly so the user can tell rotate from shift at a glance
// — important because σ0/σ1 mix both (`σ0(x) = ROTR^7(x) ⊕ ROTR^18(x) ⊕
// SHR^3(x)`, FIPS 180-4 §4.1.2).
const BitOpBlock = (props: BlockProps) => {
  const params = (): { bits?: number; wordBits?: number } => props.step.params as never;
  const bits = (): number => params().bits ?? 0;
  const wordBits = (): number => params().wordBits ?? 32;
  const operation = (): string =>
    props.step.type === "rotate-bits-right@1"
      ? "Cyclic rotate right (ROTR)"
      : "Logical shift right (SHR)";

  const writeBits = (next: number) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      bits: next,
    });
  };

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Operation</dt>
          <dd>{operation()}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Bits</dt>
          <dd>
            {/* max clamp = wordBits-1 for rotate (mod wordBits) and
                a sensible ceiling for shift (past wordBits the output is
                all-zeros; we leave the door open so users can prove it). */}
            <IntInput
              value={bits()}
              min={0}
              max={wordBits()}
              placeholder="0"
              onCommit={writeBits}
            />
          </dd>
        </div>
        <div class="param-scalar-row">
          <dt>Word bits</dt>
          <dd>{wordBits()}</dd>
        </div>
      </dl>
    </>
  );
};

// xor@1 / and@1 / add-mod-32@1 / concat@1 — all share `{ inputCount: number }`.
//
// Read-only: editing `inputCount` without re-wiring downstream `input0`..
// `inputN-1` ports throws "input port inputN not wired" at the next run.
// That's a hard-error path with no pedagogical signal (the user sees the
// cipher refuse to run, not a divergent digest). Locking matches the
// existing pattern (BlockSizeBlock, AddRoundKeyBlock).
const INPUT_COUNT_PARAM_TYPES = new Set([
  "xor@1",
  "and@1",
  "add-mod-32@1",
  "add-mod-16@1", // K2a (2026-06-01) — Speck schedule 16-bit modular addition.
  "concat@1",
]);

const InputCountBlock = (props: { step: StepLeaf }) => {
  const params = (): { inputCount?: number } => props.step.params as never;
  const operation = (): string => {
    switch (props.step.type) {
      case "xor@1":
        return "Bitwise XOR (⊕)";
      case "and@1":
        return "Bitwise AND (∧)";
      case "add-mod-32@1":
        return "Modular add (+ mod 2³²)";
      case "add-mod-16@1":
        return "Modular add (+ mod 2¹⁶)";
      case "concat@1":
        return "Byte concatenation (‖)";
      default:
        return props.step.type;
    }
  };

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Operation</dt>
        <dd>{operation()}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Input count</dt>
        <dd>{params().inputCount ?? "—"}</dd>
      </div>
    </dl>
  );
};

// byte-slice@1.
//
// Editable `offset` + `length` — both produce wrong-but-defined output
// when edited (the slice lands at a different position or carries a
// different number of bytes; downstream consumers see a coercion warning
// or wrong data). Read-only `sourceByteLength` — that's the declared
// upstream length used for port-contract coercion warnings; editing it
// changes what coercion the runtime performs but doesn't change the input
// itself.
const ByteSliceBlock = (props: BlockProps) => {
  const params = (): { offset?: number; length?: number; sourceByteLength?: number } =>
    props.step.params as never;
  const offset = (): number => params().offset ?? 0;
  const length = (): number => params().length ?? 0;

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Offset (bytes)</dt>
        <dd>
          <IntInput
            value={offset()}
            min={0}
            placeholder="0"
            onCommit={(next) => writeParams({ offset: next })}
          />
        </dd>
      </div>
      <div class="param-scalar-row">
        <dt>Length (bytes)</dt>
        <dd>
          <IntInput
            value={length()}
            min={1}
            placeholder="1"
            onCommit={(next) => writeParams({ length: next })}
          />
        </dd>
      </div>
      <div class="param-scalar-row">
        <dt>Source byteLength</dt>
        <dd>{params().sourceByteLength ?? "—"}</dd>
      </div>
    </dl>
  );
};

// aux-load-bytes@1.
//
// Editable `auxName` (renaming retargets the aux read — same pattern as
// AuxLoadBlock for `aux-load@1`). Read-only `byteLength` — declared
// PortContract output length used for coercion warnings; editing it without
// matching the actual aux value's length surfaces a warning but doesn't
// change runtime behavior, so locking it keeps the surface honest.
const AuxLoadBytesBlock = (props: { step: StepLeaf }) => {
  const spec = useSpec();
  const params = (): { auxName?: string; byteLength?: number } => props.step.params as never;

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  // Back-ref (scaffolding-suppression A1): if this leaf reads an aux key
  // that's a published cipher constant, name it as a clickable link that
  // scrolls the constants panel's matching row into view. Closes the loop
  // with the panel's forward cross-ref (which links the other direction).
  const constantName = createMemo<string | null>(() => {
    const n = params().auxName;
    const constants = spec().cipherConstants;
    return n && constants && n in constants ? n : null;
  });

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Aux name (read)</dt>
        <dd>
          <AuxNameInput
            value={params().auxName ?? ""}
            placeholder="aux key to read bytes from"
            onCommit={(v) => writeParams({ auxName: v })}
          />
        </dd>
      </div>
      <div class="param-scalar-row">
        <dt>Declared byteLength</dt>
        <dd>{params().byteLength ?? "—"}</dd>
      </div>
      <Show when={constantName()}>
        {(name) => (
          <div class="param-scalar-row">
            <dt>Reads constant</dt>
            <dd>
              <button
                type="button"
                class="constant-backref-link"
                title={`Scroll to "${name()}" in the cipher-constants panel`}
                onClick={() => {
                  document
                    .querySelector(`[data-constant-row="${name()}"]`)
                    ?.scrollIntoView({ behavior: "smooth", block: "center" });
                }}
              >
                {name()}
              </button>
            </dd>
          </div>
        )}
      </Show>
    </dl>
  );
};

// split-bytes@1.
//
// Read-only `widths` array — same rationale as InputCountBlock: editing
// produces "output port outputN not wired" downstream errors. Display as
// comma-separated values to give the user a quick read of the split shape
// (e.g. SHA-256's per-round working-variable split is `[4, 4, 4, 4, 4, 4,
// 4, 4]` for 8 words of 4 bytes each).
const SplitBytesBlock = (props: { step: StepLeaf }) => {
  const params = (): { widths?: readonly number[] } => props.step.params as never;
  const widths = (): readonly number[] => params().widths ?? [];
  const total = (): number => widths().reduce((sum, w) => sum + w, 0);

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Output count</dt>
          <dd>{widths().length}</dd>
        </div>
        <div class="param-scalar-row">
          <dt>Total byteLength</dt>
          <dd>{total()}</dd>
        </div>
      </dl>
      <div class="param-section">
        <div class="param-section-label">Widths (bytes per output)</div>
        {/* Comma-separated read-only chip row; matches the visual weight of
            other read-only scalar rows but lets the user see the array
            shape at a glance without a JSON dump. */}
        <div class="param-readonly-array">
          <For each={widths()}>
            {(w, i) => <span class="param-readonly-cell">{`[${i()}] ${w}`}</span>}
          </For>
        </div>
      </div>
    </>
  );
};

// constant-load@1.
//
// Read-only hex dump of `bytes`. Editing would conceptually be valid (the
// PortContract declares the output length as a function of `params.bytes`),
// but the SHA-256 spec carries two large constants (256-byte K table, 32-byte
// H table) that aren't pedagogical to edit byte-by-byte — the user's
// natural lever is the rotation constants in σ/Σ, not the SHA constants.
// Locking matches the spirit of "the canonical FIPS tables are the canonical
// state."
const ConstantLoadBlock = (props: { step: StepLeaf }) => {
  const params = (): { bytes?: readonly number[] } => props.step.params as never;
  const bytes = (): readonly number[] => params().bytes ?? [];
  const hex = (): string => formatBytes(Uint8Array.from(bytes()), "hex");

  return (
    <>
      <dl class="param-scalars">
        <div class="param-scalar-row">
          <dt>Constant byteLength</dt>
          <dd>{bytes().length}</dd>
        </div>
      </dl>
      <details class="param-section param-collapsible">
        <summary class="param-section-label">
          Bytes ({bytes().length} entries, hex — click to expand)
        </summary>
        <pre class="param-hex-dump">{hex()}</pre>
      </details>
    </>
  );
};

// pad-with-byte@1.
//
// Editable `padByte` (the sentinel byte; SHA-256 uses 0x80 per FIPS 180-4
// §5.1.1) and `padTarget` (the byte index the padded output should end at
// — 56 for single-block SHA-256, leaving 8 bytes for the length suffix).
// Read-only `blockSize` (structural; load-block and append-be64-length
// assume 64 for SHA-256).
const PadWithByteBlock = (props: BlockProps) => {
  const params = (): { padByte?: number; padTarget?: number; blockSize?: number } =>
    props.step.params as never;

  const writeParams = (patch: Record<string, Json>) => {
    editStepParams(props.step.id, {
      ...(props.step.params as Record<string, Json>),
      ...patch,
    });
  };

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Pad byte (sentinel)</dt>
        <dd>
          <ByteCellInput
            value={params().padByte ?? 0}
            onCommit={(next) => writeParams({ padByte: next })}
          />
        </dd>
      </div>
      <div class="param-scalar-row">
        <dt>Pad target (output byte index)</dt>
        <dd>
          <IntInput
            value={params().padTarget ?? 0}
            min={0}
            max={(params().blockSize ?? 64) - 1}
            placeholder="0"
            onCommit={(next) => writeParams({ padTarget: next })}
          />
        </dd>
      </div>
      <div class="param-scalar-row">
        <dt>Block size</dt>
        <dd>{params().blockSize ?? "—"} bytes</dd>
      </div>
    </dl>
  );
};

// not@1 / state-to-bytes@1 / bytes-to-state@1 / append-be64-length@1 —
// every one has empty params. Render an explanatory blurb instead of the
// raw-JSON fallback's empty `{}`. Re-uses NoParamsBlock (defined above
// for Serpent's linear transforms).
const NO_PARAMS_PORT_NATIVE_TYPES = new Set([
  "not@1",
  "state-to-bytes@1",
  "bytes-to-state@1",
  "append-be64-length@1",
  "keccak.theta@1",
  "increment-counter@1",
]);

const portNativeNoParamsLabel = (stepType: string): string => {
  switch (stepType) {
    case "not@1":
      return "Bitwise NOT (¬) — flips every bit. No editable parameters; operates byte-by-byte.";
    case "state-to-bytes@1":
      return "Bridges runtime state → port-native bytes (identity-on-port). No editable parameters; the conversion is driven by the runtime's state codec.";
    case "bytes-to-state@1":
      return "Bridges port-native bytes → runtime state (identity-on-port). No editable parameters; the conversion is driven by the runtime's state codec.";
    case "append-be64-length@1":
      return "Appends the big-endian 64-bit bit-length of the message (FIPS 180-4 §5.1.1). No editable parameters; the length is derived from the input port's byteLength.";
    case "increment-counter@1":
      return "Adds one to the counter block, read as a big-endian number (NIST SP 800-38A §6.5). No editable parameters; the counter's width is the cipher's block size, taken from the wired input.";
    case "keccak.theta@1":
      return "θ (theta) — mixes whole columns of the Keccak state (FIPS 202 §3.2.1). No editable parameters; the 5×5×64 geometry is fixed.";
    default:
      return "No editable parameters.";
  }
};

// ─── Apply-to-all button ─────────────────────────────────────────────────

// ─── Sync-inverse-to-counterpart button ─────────────────────────────────
//
// Cross-mode value-mirror affordance for substitution tables. Sits below
// ApplyAllRow so the two propagation surfaces — within-mode (`Apply to
// all`) and across-mode (this) — are vertically adjacent and read as a
// matched pair.
//
// Design rationale (see comment on `syncSboxInverseToCounterpart` in
// stores/spec.ts):
//   - Encrypt's forward S-box and decrypt's inverse S-box are *algebraic
//     inverses*, not equal. A naive sync (copy-paste) would corrupt the
//     decrypt path. We invert the current forward table and write the
//     inverse to the counterpart slot.
//   - Disabled when the current table is not a permutation — the inverse
//     is undefined for a non-bijection. The Repair button (in
//     SboxEditor's banner) is the prerequisite; tooltip routes users
//     there explicitly.
//   - Operation is involutive: invertSbox(invertSbox(x)) === x. So
//     editing the inverse table in decrypt mode and clicking sync writes
//     the forward back to encrypt with the same algorithm — only the
//     label changes.
const SyncInverseRow = (props: {
  currentSbox: readonly number[];
  stepType: string;
  // Role-scope filter (key-schedule-decomposition K1c): when set, the
  // inverse is broadcast only to counterpart leaves whose id passes this
  // predicate. `byte-substitute@1` passes `isRoundBodyLeafId` so the
  // key-schedule SubWord leaves are NOT overwritten with the inverse table.
  idFilter?: (id: string) => boolean;
}) => {
  const mode = useMode();
  const isBijective = (): boolean => countRedundantDuplicates(props.currentSbox) === 0;
  const counterpartLabel = (): string => (mode() === "encrypt" ? "decrypt" : "encrypt");
  const buttonLabel = (): string => `Sync inverse S-box to ${counterpartLabel()}`;
  const disabledTooltip =
    "Repair to a permutation first — the inverse is undefined for a non-bijective table.";

  return (
    <div class="sync-inverse-row">
      {/* Wrapped in ActionButton: clicking writes to every counterpart-
          mode step at once, but the user is viewing the active mode's
          panel — without the flash they have no visible signal that
          anything happened. feedbackLabel names the operation so screen
          readers also hear what propagated. */}
      <ActionButton
        disabled={!isBijective()}
        title={
          isBijective()
            ? `Compute the inverse of this S-box and write it to every ${props.stepType} step in the ${counterpartLabel()} slot (overwrites any per-step customizations on that side).`
            : disabledTooltip
        }
        feedbackLabel={`Synced inverse S-box to ${counterpartLabel()} mode`}
        // Surface the architectural class (inverse-mirror) on the DOM so
        // the cross-mode-mirror-coverage enumeration test can assert "a
        // button with the right mirror class is present for every entry
        // in the registry." Keeps the principle mechanically enforced
        // rather than only documented in prose.
        data-mirror-class="inverse"
        onAction={() => {
          if (!isBijective()) return; // belt-and-braces; button is disabled too
          const inverted = invertSbox(props.currentSbox);
          syncSboxInverseToCounterpart(props.stepType, inverted, props.idFilter);
        }}
      >
        {buttonLabel()}
      </ActionButton>
    </div>
  );
};

// ─── Copy-S-box-to-counterpart button ────────────────────────────────────
//
// Class-1 (identity) cross-mode mirror affordance. Used today by
// `aes.key-expansion@1` / `@2`: FIPS-197 §5.2 says the key schedule uses
// the FORWARD S-box even when decrypting, so encrypt and decrypt hold the
// SAME table — not algebraic inverses. The button label deliberately says
// "Copy" (not "Sync inverse") so the user reads the asymmetry between
// SubBytes (inverse-mirrored, separate button) and KeyExpansion (identity-
// mirrored) before clicking.
//
// Why we gate on bijection even though a copy is mathematically valid for
// a non-permutation: behavioral coherence with the inverse rows. If half
// the S-box rows lock when broken and the other half don't, users will
// learn a noisier mental model. Repair-first is the single rule for
// every S-box mirror row.
const CopySboxRow = (props: {
  currentSbox: readonly number[];
  stepType: string;
  // Role-scope filter (key-schedule-decomposition K1c): when set, the Copy
  // is broadcast only to counterpart leaves whose id passes this predicate.
  // `byte-substitute@1` passes `isKeyScheduleLeafId` so the Copy lands on
  // the key-schedule SubWord leaves and NOT the round-body SubBytes leaves.
  idFilter?: (id: string) => boolean;
}) => {
  const mode = useMode();
  const isBijective = (): boolean => countRedundantDuplicates(props.currentSbox) === 0;
  const counterpartLabel = (): string => (mode() === "encrypt" ? "decrypt" : "encrypt");
  const buttonLabel = (): string => `Copy S-box to ${counterpartLabel()}`;
  const disabledTooltip =
    "Repair to a permutation first — copying a non-permutation still copies, but the table is unlikely to be useful and we gate every S-box mirror row the same way for consistency.";
  const enabledTooltip = (): string =>
    `Copy this S-box verbatim to every ${props.stepType} step in the ${counterpartLabel()} slot. FIPS-197 §5.2: key expansion uses the FORWARD S-box even when decrypting, so the same table appears on both sides (this overwrites any per-step customizations on that side).`;

  return (
    <div class="copy-sbox-row">
      <ActionButton
        disabled={!isBijective()}
        title={isBijective() ? enabledTooltip() : disabledTooltip}
        feedbackLabel={`Copied S-box to ${counterpartLabel()} mode`}
        // Surfaced for the cross-mode-mirror-coverage test (Slice 4). The
        // `data-mirror-class="identity"` value tells the enumeration test
        // this row implements the class-1 (same-value) mirror, vs. the
        // class-2 (algebraic-inverse) rows above.
        data-mirror-class="identity"
        onAction={() => {
          if (!isBijective()) return; // belt-and-braces; button is disabled
          // Pass the current table verbatim — NO `invertSbox` composition
          // here. The whole point of the Copy verb is to mirror the
          // forward S-box exactly, per FIPS-197 §5.2.
          syncSboxCopyToCounterpart(props.stepType, props.currentSbox, props.idFilter);
        }}
      >
        {buttonLabel()}
      </ActionButton>
    </div>
  );
};

// ─── Sync-inverse-MixColumns-to-counterpart button ───────────────────────
//
// Class-2 (algebraic-inverse) cross-mode mirror for the MixColumns matrix.
// Encrypt holds the forward mixing matrix (canonically `AES_MIX_MATRIX`);
// decrypt holds its GF(2^8) inverse (canonically `AES_INV_MIX_MATRIX`,
// FIPS-197 §5.3.3). The button computes the inverse via Gauss-Jordan over
// GF(2^8) (`gfMatInverse4x4`) and broadcasts it to every counterpart-side
// `generic.mix-columns@1` leaf.
//
// **Gating via try/catch (advisor pick):** the inverter throws on singular
// matrices, so we wrap `gfMatInverse4x4` in a `createMemo` and use the
// catch path as the disabled-state signal. No duplicated invertibility
// check; the inverter IS the check. The memo also caches the result so
// the onAction handler doesn't re-run the elimination.
//
// **No "Repair" affordance** unlike S-boxes: a singular 4×4 matrix has no
// general repair recipe (the canonical AES matrix is one specific
// invertible table among many). The tooltip says so honestly — the user
// has to edit a cell to recover invertibility.
const SyncMixColumnsRow = (props: {
  currentMatrix: readonly (readonly number[])[];
  stepType: string;
}) => {
  const mode = useMode();
  const counterpartLabel = (): string => (mode() === "encrypt" ? "decrypt" : "encrypt");
  const buttonLabel = (): string => `Sync inverse MixColumns to ${counterpartLabel()}`;

  // Memo-wrapped inverse: either the computed inverse matrix, or null if
  // the current matrix is singular over GF(2^8). The catch path IS the
  // gating signal — no separate `isInvertible` predicate.
  const inverseMatrix = createMemo<readonly (readonly number[])[] | null>(() => {
    try {
      return gfMatInverse4x4(props.currentMatrix);
    } catch {
      return null;
    }
  });
  const isInvertible = (): boolean => inverseMatrix() !== null;

  const disabledTooltip =
    "This matrix has no inverse over GF(2^8) (singular). Edit a cell to restore invertibility — unlike the S-box editor, there's no general 'Repair' recipe for a 4×4 mixing matrix, since the canonical AES matrix is just one specific invertible table among many.";
  const enabledTooltip = (): string =>
    `Compute the GF(2^8) inverse of this matrix (Gauss-Jordan, FIPS-197 §5.3.3) and write it to every ${props.stepType} step in the ${counterpartLabel()} slot (overwrites any per-step customizations on that side).`;

  return (
    <div class="sync-mix-columns-row">
      <ActionButton
        disabled={!isInvertible()}
        title={isInvertible() ? enabledTooltip() : disabledTooltip}
        feedbackLabel={`Synced inverse MixColumns to ${counterpartLabel()} mode`}
        // Class-2 inverse-mirror — same value the SbxBlock/SerpentSubBytes
        // rows surface. The enumeration coverage test
        // (`tests/cross-mode-mirror-coverage.test.tsx`) walks the registry
        // and asserts every entry has a button with the matching class.
        data-mirror-class="inverse"
        onAction={() => {
          const inverse = inverseMatrix();
          if (!inverse) return; // belt-and-braces; button is disabled
          syncMixColumnsInverseToCounterpart(props.stepType, inverse);
        }}
      >
        {buttonLabel()}
      </ActionButton>
    </div>
  );
};

const ApplyAllRow = (props: {
  currentParams: Json;
  stepType: string;
  matchingCount: number;
  label: string;
}) => (
  <Show when={props.matchingCount > 1}>
    <div class="apply-all-row">
      {/* The mutation writes to (matchingCount - 1) steps the user
          isn't currently viewing. Without the flash, only the active
          step shows a "modified" state changing, so the user can't see
          that the propagation actually happened. */}
      <ActionButton
        title={`Copy this step's ${props.label} to all ${props.matchingCount} steps of type ${props.stepType}`}
        feedbackLabel={`Applied ${props.label} to all ${props.matchingCount} matching steps`}
        onAction={() => {
          // The update fn replaces every matching step's params with this
          // step's exact current params. That's stronger than just copying
          // one field, but for AES our generic step types have only one
          // meaningful field anyway.
          editAllStepsByType(props.stepType, () => props.currentParams);
        }}
      >
        Apply this {props.label} to all {props.matchingCount} matching steps
      </ActionButton>
    </div>
  </Show>
);
