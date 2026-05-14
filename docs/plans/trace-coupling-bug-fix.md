# Trace-coupling bug fix

Three editor-flow bugs share one root cause: the graph view's affordances
(orphan warnings, ParamEditor selection, replicate fan-out) all depend on
a trace, but the trace doesn't run before the user clicks "Run" for the
first time. A fourth reported bug (palette drops always append at bottom)
is a separate UX feedback gap, NOT a logic bug — diagnosed but deferred to
a follow-up polish pass.

This plan implements **option 1 + option 3a** from the design discussion
(2026-05-14 session, advisor-consulted). Option 3b (static spec validator)
is intentionally deferred until the Feistel branching data model settles.

## Context

### Bugs reported

1. **No warning glyph on a dropped aux-xor** with empty params, even
   though `tests/aux-primitives.test.ts:267` claims to pin this exact
   regression. The unit test verifies `runSpec → validateGraph`; the
   broken flow is `editor drops aux-xor → no run → empty trace →
   validateGraph emits nothing`.
2. **Click on a newly dropped leaf doesn't open the params panel.**
   `ParamEditor` takes `frame: TraceFrame | null` and resolves the step
   via the frame's stepId; no frame → "no step selected" fallback.
3. **Replicate fan-out toggle has no visible effect.** `replicateHighFanoutSources`
   operates on aux edges; aux edges come from trace frames; no trace →
   no aux edges → nothing to replicate. The user's "all arrows are white"
   observation matches state edges (white, derivable from spec alone)
   showing without aux edges (which need trace data).
4. **Palette drops always append at bottom.** Verified across four drop
   targets (leaf `<g>`, inner `<rect>`, container body, empty SVG) —
   the drop-anchor walk works exactly as designed. Bug 4 is a UX
   feedback gap: no dragover highlight on the would-be-anchor, so the
   user can't see what they're aiming at before releasing.

### Root cause for bugs 1+2+3

`App.tsx:186` initializes `hasRunOnce = false`. The `createEffect(on(spec, ...))`
auto-rerun chain at `App.tsx:578` early-returns when `hasRunOnce` is
false. So spec mutations before the user's first manual Run *do nothing*
— no trace ever materializes. `rawGraph` at `GraphView.tsx:649` falls
back to an empty-frames trace (structural skeleton renders), but
`validateGraph` walks `trace.frames` to find `auxReadMissing` — empty
frames means zero warnings.

### Why bug 3 isn't fixed by option 3b

Option 3b proposed a static spec validator that infers aux-key
producer/consumer relationships from each step's *params* (without
needing executed frames). That fixes orphan-read warnings (bug 1) but
NOT fan-out replication. Aux fanout is genuinely a runtime property —
the producer→consumer edges (e.g., key-expansion → each per-block
AddRoundKey in a multi-block iterate) require actual execution to count
correctly. Static analysis can declare "this step would read aux X" but
can't produce the realistic edge structure that `replicateHighFanoutSources`
needs.

### Why 3b is deferred until Feistel lands

3b's static walker has to encode "consecutive same-parent leaves share
state" to know which aux producers are upstream of which consumers.
Feistel-style ciphers with branching state (left/right halves evolving
independently inside a round body) break that invariant. Today's
`deriveAuxGraph` already needs revisiting for Feistel per CLAUDE.md's
"Feistel future" callout — 3b would inherit the same revisit cost.
Don't pay it twice. Land 3b after the branching data model is settled.

## Critical files

- `src/ui/App.tsx` — `run()` function, the `hasRunOnce` signal, the
  `createEffect(on(spec, ...))` auto-rerun, the `<ParamEditor>` mount
  with `frame={currentFrame()}`.
- `src/ui/components/ParamEditor.tsx` — `Props = { frame: TraceFrame | null }`,
  `step()` derived from `findStep(spec, frame.stepId)`.
- `src/ui/components/GraphView.tsx` — `handleLeafClick(stepId)` at line
  811, which calls `setFrame(idx)` after looking up `idx` in the trace.
- `src/ui/stores/trace.ts` — current home of `frameIndex` and `setFrame`;
  natural place to add a `selectedStepId` signal, OR a new
  `src/ui/stores/selection.ts` for separation of concerns.

## Plan

### Phase 1 — Empirical confirmation (10 min)

Before changing code, write a focused test that pins the theory. Render
the App, switch to graph view *without* clicking Run, drop aux-xor (via
`fireDropAt` on a leaf with `data-drop-anchor`), assert no warnings
appear. Then explicitly call `run()` and assert warnings now appear.

- File: `tests/trace-coupling-repro.test.tsx`
- If the test fails (warning appears even before Run), the theory's
  wrong and the rest of this plan is wrong-sized — go back to advisor.

### Phase 2 — Option 1: onMount auto-run (~1 line)

In `App.tsx`, add `onMount(() => run())` to fire a boot-time run with
the default key + plaintext.

- The existing `run()` at `App.tsx:316` already has a try/catch that
  calls `setError(err.message)`. Boot errors (e.g., malformed
  URL-hash spec, invalid saved file) surface in the existing error
  banner without code changes.
- Side benefit: matrix views and state visualizations populated on
  app boot. Users see "look at this working AES" without clicking.

Test additions:
- After App render, `getTrace()` returns non-null.
- A malformed URL-hash spec triggers `setError` on boot (existing
  catch handles it; verify no double-error path).

### Phase 3 — Option 3a: ParamEditor takes stepId, not frame (~30 lines + 1 test)

Decouple ParamEditor from the trace. Two reasons:
1. **Bug 2 fix.** A step with no trace frame (e.g., inserted after a
   step that threw) should still be editable — the params live on the
   spec, not the frame.
2. **Robustness.** When a run errors partway through, frames exist for
   early steps but not late ones. ParamEditor should resolve to any
   step the user clicks, regardless of frame state.

Change shape:

```ts
// ParamEditor.tsx — prop signature
type Props = {
  stepId: string | null;  // was: frame: TraceFrame | null
};
// step() derivation
const step = (): StepLeaf | null => {
  const id = props.stepId;
  return id ? findStep(spec(), id) : null;
};
```

```ts
// stores/trace.ts (or a new stores/selection.ts)
const [selectedStepId, setSelectedStepId] = createSignal<string | null>(null);
export const useSelectedStepId = () => selectedStepId;
```

```ts
// GraphView.tsx — handleLeafClick
const handleLeafClick = (stepId: string): void => {
  setSelectedStepId(stepId);  // NEW — works regardless of trace
  void version();
  const t = getTrace();
  if (!t) return;
  const idx = t.frames.findIndex(...);
  if (idx >= 0) setFrame(idx);  // trace-coupled views still update
};
```

```ts
// App.tsx — ParamEditor mount
<ParamEditor stepId={selectedStepId()} />
// was: <ParamEditor frame={currentFrame()} />
```

Test additions:
- `tests/param-editor-no-trace.test.tsx`: render App, switch to graph
  view, click a leaf without running, assert ParamEditor renders the
  step's params (not the "no step selected" fallback).

## Out of scope

- **Option 3b** (static spec validator for orphan reads). Defer until
  Feistel branching data model settles. Track in
  `docs/plans/duplicate-round.md` cross-reference + the project memory
  pointer.
- **Bug 4** (drag-time anchor highlighting). Pure UX polish; can ship
  as a follow-up after the duplicate-round work. Concretely: in
  `GraphView`'s `handleDragOver`, walk `closest("[data-drop-anchor]")`
  on the target and set a `hoveredAnchorId` signal. CSS rule
  `[data-drop-anchor].drop-target-active { stroke: var(--accent);
  stroke-width: 2; }` highlights the rect.

## Testing strategy

The new tests target the *editor flow*, not just the runtime path —
that's the gap the existing `aux-primitives.test.ts:267` test missed.
Two files, both jsdom:

- `tests/trace-coupling-repro.test.tsx` — the no-trace baseline (phase 1).
- `tests/param-editor-no-trace.test.tsx` — ParamEditor resolves
  without a frame (phase 3).

Existing tests stay green: `aux-primitives.test.ts:267` continues to pin
the runtime path; `built-from-palette-roundtrip.test.tsx` continues to
pin the full Save→Load flow (which already calls Run inside its setup).

## Estimate

~31 lines + 2 tests. Half a day for an experienced hand.
