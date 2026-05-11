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

import { findStep } from "@/core/spec-mutations";
import type { Json, StepLeaf, TraceFrame } from "@/core/types";
import { For, Match, Show, Switch } from "solid-js";
import { editAllStepsByType, editStepParams, useSpec } from "../stores/spec";
import { ByteCellInput } from "./ByteCellInput";
import { MatrixEditor } from "./MatrixEditor";
import { SboxEditor } from "./SboxEditor";
import { ShiftsEditor } from "./ShiftsEditor";

type Props = {
  /** The frame whose step we should be editing — typically the active frame. */
  frame: TraceFrame | null;
};

export const ParamEditor = (props: Props) => {
  const spec = useSpec();

  // Resolve the frame's stepId back to the live spec leaf. We don't trust
  // the frame's own params because the spec may have been edited since the
  // frame was emitted — the spec is the source of truth.
  const step = (): StepLeaf | null => {
    const f = props.frame;
    if (!f) return null;
    return findStep(spec(), f.stepId);
  };

  const matchingSteps = (): number => {
    const s = step();
    if (!s) return 0;
    // Count how many leaves share this step's type — used by the
    // "Apply to all N steps" button label.
    let count = 0;
    const visit = (
      nodes: readonly { kind: string; type?: string; children?: readonly unknown[] }[],
    ): void => {
      for (const node of nodes) {
        if (node.kind === "step" && node.type === s.type) count++;
        else if (node.kind === "group") visit(node.children as never);
      }
    };
    visit(spec().steps as never);
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
            <Match when={getStep().type === "aes.key-expansion@1"}>
              <KeyExpansionBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "generic.add-round-key@1"}>
              <AddRoundKeyBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={BLOCK_SIZE_PARAM_TYPES.has(getStep().type)}>
              <BlockSizeBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match when={getStep().type === "speck.key-schedule@1"}>
              <SpeckKeyScheduleBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
            <Match
              when={
                getStep().type === "speck.round@1" || getStep().type === "speck.round-inverse@1"
              }
            >
              <SpeckRoundBlock step={getStep()} matchingCount={matchingSteps()} />
            </Match>
          </Switch>
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

// Speck key-schedule block.
//
// All seven params are structural (cipher-defining constants or naming
// hooks); we render them read-only as a scalars dl. Mirrors the shape of
// KeyExpansionBlock's scalars row but without the embedded S-box / rcon
// editors — Speck has no S-box, and its "round constant" is just the
// loop counter `i` XOR'd into the schedule (no table to edit).
//
// No ApplyAllRow: there's only one key-schedule step in any Speck spec.
const SpeckKeyScheduleBlock = (props: BlockProps) => {
  const params = (): {
    keyAuxName?: string;
    outputPrefix?: string;
    rounds?: number;
    wordBits?: number;
    m?: number;
    alpha?: number;
    beta?: number;
    byteOrder?: string;
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
        <dt>Rounds</dt>
        <dd>{params().rounds ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Word bits (n)</dt>
        <dd>{params().wordBits ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Key words (m)</dt>
        <dd>{params().m ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>α (ROR)</dt>
        <dd>{params().alpha ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>β (ROL)</dt>
        <dd>{params().beta ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Byte order</dt>
        <dd>{params().byteOrder ?? "—"}</dd>
      </div>
    </dl>
  );
};

// Speck round / round-inverse block.
//
// Five structural params shared by both forward and inverse steps. The
// `roundKeyAux` is the per-leaf knob that wires the round to its specific
// round-key word; pinning it visible makes the encrypt-vs-decrypt key
// ordering (`roundKey.0` first vs. `roundKey.21` first) inspectable when
// scrubbing through the trace.
//
// No ApplyAllRow: like AddRoundKey, each Speck round leaf intentionally
// references a DIFFERENT roundKey aux name. Copying one step's params
// onto every match would point every round at the same key.
const SpeckRoundBlock = (props: BlockProps) => {
  const params = (): {
    roundKeyAux?: string;
    alpha?: number;
    beta?: number;
    wordBits?: number;
    byteOrder?: string;
  } => props.step.params as never;

  return (
    <dl class="param-scalars">
      <div class="param-scalar-row">
        <dt>Round key aux</dt>
        <dd>{params().roundKeyAux ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>α (ROR)</dt>
        <dd>{params().alpha ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>β (ROL)</dt>
        <dd>{params().beta ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Word bits (n)</dt>
        <dd>{params().wordBits ?? "—"}</dd>
      </div>
      <div class="param-scalar-row">
        <dt>Byte order</dt>
        <dd>{params().byteOrder ?? "—"}</dd>
      </div>
    </dl>
  );
};

// ─── Apply-to-all button ─────────────────────────────────────────────────

const ApplyAllRow = (props: {
  currentParams: Json;
  stepType: string;
  matchingCount: number;
  label: string;
}) => (
  <Show when={props.matchingCount > 1}>
    <div class="apply-all-row">
      <button
        type="button"
        title={`Copy this step's ${props.label} to all ${props.matchingCount} steps of type ${props.stepType}`}
        onClick={() => {
          // The update fn replaces every matching step's params with this
          // step's exact current params. That's stronger than just copying
          // one field, but for AES our generic step types have only one
          // meaningful field anyway.
          editAllStepsByType(props.stepType, () => props.currentParams);
        }}
      >
        Apply this {props.label} to all {props.matchingCount} matching steps
      </button>
    </div>
  </Show>
);
