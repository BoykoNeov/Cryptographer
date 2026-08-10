/**
 * Per-frame value-prose surface — Phase 1 of the narration rollout.
 *
 * Renders below `<MatrixView />` in linear mode. For each frame, looks
 * up a narration fn for the step type, builds the unit list, and
 * renders one collapsible `<details>` per conceptual sub-unit (row,
 * column, byte, cell — chosen per step). Each `<details>` body is a
 * `Component<{fmt}>` so the byte-format toggle surgically updates
 * prose text without recreating the `<details>` (which would snap it
 * shut).
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
 * resets accordingly — consistent across the linear-mode panes.
 */

import type { TraceFrame } from "@/core/types";
import { Index, Show, createMemo } from "solid-js";
import { Dynamic } from "solid-js/web";
import { type NarrationUnit, lookupNarration } from "../narration/registry";
import { useByteFormat } from "../stores/format";

type Props = {
  frame: TraceFrame;
};

/**
 * Why `<Index>` not `<For>` (the critical reactivity contract):
 *
 * `App.tsx` runs a debounced 200ms re-run on any change to
 * `[spec, inputText, keyText, ivBytes]`. The byte-format toggle
 * re-renders `inputText` (parse with old format → re-format with new),
 * which triggers that re-run. The runtime produces a new `Trace`,
 * `App.frame()` now points to a fresh `TraceFrame` object (same
 * `stepId`, new reference), `<StepNarration>` receives the new frame,
 * `units` memo re-runs, and the narrator builds an entirely new units
 * array — every `unit.Prose` is a fresh closure with new captured
 * bytes, and every `unit` is a new object.
 *
 * `<For>` is keyed by item reference. After a re-run, every item is
 * "new," so `<For>` unmounts every `<details>` and creates fresh ones —
 * destroying the browser-native `open` state on any expanded
 * disclosure. The format-toggle UX snaps open rows shut.
 *
 * `<Index>` keys by position. The `<details>` element at position N
 * persists across re-runs; only the reactive bindings inside (the
 * summary label, the Prose component) re-evaluate. The `open`
 * attribute lives on the persisted element so the browser keeps the
 * row expanded. The Prose's JSX (which reads `props.fmt` inline) then
 * surgically updates the byte text inside the body.
 *
 * Per-step narrators produce a stable order per `stepType` (16 byte
 * units for SubBytes, 4 row units for ShiftRows, etc.), so `Index`'s
 * position-key is conceptually stable — position N always corresponds
 * to the same conceptual sub-unit.
 *
 * **Cardinality, however, may vary — TRAILING units can be conditional.**
 * This was an unqualified "always the same cardinality" until the lattice
 * narrators landed (2026-08-10): `zq-decompress@1` adds a row only at
 * `d = 1` (where the step is the message entering the ring) and
 * `ml-kem.hash-g@1` adds one only at its key-generation call site. A
 * trailing row's ROLE may swap too, not merely its presence:
 * `zq-compress@1` keeps three rows either way, but its third is about
 * ciphertext size at `d = 10 / 4` and about recovering the message at
 * `d = 1`.
 *
 * All of that stays compatible with `<Index>` precisely because the
 * variation is at the TAIL — Solid adds, removes or re-evaluates the last
 * `<details>` and leaves the preceding ones in place, so no earlier row's
 * `open` state is disturbed. A narrator that inserted or removed a unit in
 * the MIDDLE would silently shift every row below it onto a different
 * position key, and would need `<For>` with an explicit key instead. Don't
 * do that; append conditional rows.
 *
 * `<Dynamic component={unit.Prose}>` is the correct primitive for the
 * dynamic component reference: when `unit()` returns a new unit with a
 * new Prose closure, `<Dynamic>` swaps the inner render WITHOUT
 * touching the `<details>` ancestor.
 */
export const StepNarration = (props: Props) => {
  const fmt = useByteFormat();

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
          <Index each={getUnits()}>
            {(unit) => (
              <details class="step-narration-unit" data-key={unit().key}>
                <summary class="step-narration-unit-summary">{unit().label}</summary>
                <div class="step-narration-unit-prose">
                  <Dynamic component={unit().Prose} fmt={fmt()} />
                </div>
              </details>
            )}
          </Index>
        </section>
      )}
    </Show>
  );
};
