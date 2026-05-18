/**
 * Per-frame value-prose surface — Phase 1 of the narration rollout.
 *
 * Renders below `<MatrixView />` in linear mode. For each frame, looks
 * up a narration fn for the step type, builds the unit list, and
 * renders one collapsible `<details>` per conceptual sub-unit (row,
 * column, byte, cell — chosen per step). Each `<details>` body is a
 * `Component<{fmt}>` so the byte-format toggle surgically updates
 * prose text without recreating the `<details>` (which would snap it
 * shut). See the reactivity rationale at
 * `src/ui/components/KeyScheduleExplorer.tsx:295-304`.
 *
 * Dispatch:
 *   - `lookupNarration(stepType)` → narrator fn, or null.
 *   - Narrator returns unit list, or null when params/aux are malformed.
 *   - Either null path → component renders nothing for that frame.
 *
 * The component is intentionally cipher-agnostic. New step types land
 * by registering in `src/ui/narration/index.ts` (or by allowlisting
 * in `registry.ts` with a rationale). The contract test at
 * `tests/narration-registry-contract.test.ts` gates the choice.
 *
 * Non-goal: preserving `<details>` `open` state across frame swaps.
 * The unit list rebuilds per frame, which Solid renders as a new
 * `<For>` iteration; native `<details>` state lives in the DOM and
 * resets accordingly. `KeyScheduleExplorer` doesn't preserve it
 * either; pattern is consistent across the linear-mode panes.
 */

import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { type NarrationUnit, lookupNarration } from "../narration/registry";
import { useByteFormat } from "../stores/format";

type Props = {
  frame: TraceFrame;
};

export const StepNarration = (props: Props) => {
  const fmt = useByteFormat();

  // Build the unit list reactively on frame swap. Format toggles do NOT
  // rebuild the list — `fmt` flows into each Prose component via props
  // and only re-renders the byte text inside open <details>.
  //
  // `visibleUnits` collapses two suppression cases (no narrator,
  // narrator declined) into a single nullable Show predicate. The
  // empty-array case must explicitly map to null so the Show fallback
  // path fires (an empty array is otherwise truthy).
  const units = createMemo<readonly NarrationUnit[] | null>(() => {
    const fn = lookupNarration(props.frame.stepType);
    return fn ? fn(props.frame) : null;
  });
  const visibleUnits = createMemo<readonly NarrationUnit[] | null>(() => {
    const u = units();
    return u && u.length > 0 ? u : null;
  });

  return (
    <Show when={visibleUnits()}>
      {(getUnits) => (
        <section class="step-narration" aria-label="step narration">
          <For each={getUnits()}>
            {(unit) => (
              <details class="step-narration-unit" data-key={unit.key}>
                <summary class="step-narration-unit-summary">{unit.label}</summary>
                <div class="step-narration-unit-prose">
                  <unit.Prose fmt={fmt()} />
                </div>
              </details>
            )}
          </For>
        </section>
      )}
    </Show>
  );
};
