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
import { Match, Show, Switch } from "solid-js";
import { editAllStepsByType, editStepParams, useSpec } from "../stores/spec";
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
