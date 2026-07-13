# Leaf inspector expanders — "all incoming values" + "what this step does"

**Status: SHIPPED 2026-07-13.** `resolveNodeFrame` + the two `<details>`
expanders (`PortFlowView` + guarded `StepNarration`) landed in `ValueInspectorBody`;
gate green (2785 pass / 2 skip), browser-smoked on a DES S-box leaf. Tier B
(always-on cell provenance) and Tier C (arithmetic ladder) remain deferred.

Bring the linear view's per-step surfaces into the **graph value inspector**
when a **leaf node** is selected, as two collapsible expanders below the
existing single-value row:

1. **All port values** — every input (and output) port of the selected leaf's
   frame, one labelled row per port. Reuses `PortFlowView`.
2. **What this step does** — the per-frame value-prose narration for the leaf.
   Reuses `StepNarration`.

This is Feature #1 + Feature #2-Tier-A from the feasibility assessment. Tier B
(always-on cell provenance) and Tier C (literal arithmetic ladder) are out of
scope.

## Context

- **Why now / who asked:** user asked for expandable buttons in the graph value
  inspector showing (1) all incoming values to a selected leaf and (2) the
  operations that produce the leaf's output. Feasibility landed on "these are the
  linear view's existing surfaces; wire them into the graph inspector."
- **Why it's cheap:** the data already lives on every port-native `TraceFrame`
  (`portInputs` / `portOutputs`, with hybrid-leaf aux reads folded into
  `portInputs` via `meta.auxReadPorts` — verified `runtime.ts:566-585`).
  `PortFlowView` and `StepNarration` both take just `{ frame }` and couple to no
  linear-view store beyond the global `useByteFormat`.
- **Scope guard:** user scoped this to "when a leaf is selected," which excludes
  endpoints/bundles and keeps the frame resolver to essentially
  `findConsumerFrame`. Not a `core/types.ts` change → no schema bump, no plan
  gate; this doc exists because the user asked for a plan.
- **Non-goals:** Tier B/C, chip/endpoint/bundle expanders, matrix-grid value
  rendering, preserving `<details>` open-state across scrubs (native reset is
  consistent with linear mode).

## Design

### 1. Frame resolver — `resolveNodeFrame` (core, testable, pure)

Add to `src/core/edge-value-lookup.ts`:

```ts
export const resolveNodeFrame = (
  nodeId: string,
  spec: CipherSpec,
  trace: Trace | null,
  currentBlockIndex: number | undefined,
): TraceFrame | null
```

Returns the representative trace frame for a node id, or `null` when there is no
single leaf frame to show:

- Endpoint pills (`CIPHER_INPUT_ID` / `INPUT_SOURCE_ID` / `CIPHER_OUTPUT_ID`) →
  `null` (the pills carry `initialState`/`finalState`, not a leaf frame).
- Numbered block-chip (`${iterateId}@block${i}`) → the iterate body's **last**
  frame at that block index (mirrors `lookupNodeValue`'s chip branch).
- Ellipsis chip (`@blockMore`) → `null`.
- Regular leaf → `findConsumerFrame(trace, nodeId, currentBlockIndex)`; if null,
  fall back through a collapsed-container id to its `terminalLeafId` frame
  (mirrors `lookupNodeValue`'s container fallback).

All helpers it needs (`findConsumerFrame`, `parseChipId`, `findBodyFramesAt`,
`findContainerById`, `terminalLeafId`) already exist in the file — this is a
re-slice of `lookupNodeValue`'s resolution, returning the frame instead of the
extracted value. No behavioural change to `lookupNodeValue`.

### 2. Inspector wiring — `ValueInspectorBody` (GraphView.tsx)

- Import `PortFlowView`, `StepNarration`, and `resolveNodeFrame`.
- Add a memo `nodeFrame()` = when `selectedTarget().kind === "node"`, call
  `resolveNodeFrame(id, spec, getTrace(), currentBlockIndex)` (same `version()` /
  `frameIndex()` deps as the existing `lookup` memo).
- After the existing kind/value `<Show>` block (currently ends ~line 9375),
  render `<Show when={nodeFrame()}>` with two native `<details>`:
  - `<summary>all port values</summary>` → `<PortFlowView frame={f} />`
  - `<summary>what this step does</summary>` → `<StepNarration frame={f} />`
  - `StepNarration` renders nothing when no narrator matches the step type —
    the `<details>` will simply be empty for those leaves; guard the second
    expander behind a "has narrator" check (`lookupNarration(f.stepType) != null`)
    so we don't show an empty disclosure.

### 3. CSS

Reuse existing `.port-flow-view` + narration styles. Add a thin
`.graph-value-inspector-expander` (details/summary) block in `app.css` for the
disclosure chrome so it reads as part of the inspector, not the linear pane.

## Critical files

- `src/core/edge-value-lookup.ts` — add `resolveNodeFrame` (new export;
  `lookupNodeValue` untouched).
- `src/ui/components/GraphView.tsx` — `ValueInspectorBody`: imports + `nodeFrame`
  memo + two `<details>` expanders after the value row.
- `src/ui/components/PortFlowView.tsx` — reused as-is (no change).
- `src/ui/components/StepNarration.tsx` — reused as-is (no change).
- `src/ui/narration/registry.ts` — `lookupNarration` reused for the has-narrator
  guard.
- `src/ui/app.css` — `.graph-value-inspector-expander` disclosure styling.
- `tests/node-value-lookup.test.ts` — unit-test `resolveNodeFrame` (leaf, chip,
  endpoint→null, container fallback).
- `tests/graph-view-value-inspector.test.tsx` (or a new
  `graph-inspector-leaf-expanders.test.tsx`) — jsdom: select a leaf → both
  expanders present; port rows render; narration renders for a narrated leaf and
  the second expander is absent for a non-narrated leaf.

## Verify

- `npm run check` (biome + tsc + vitest + build).
- Browser smoke: `npm run dev`, graph view, select an AES round leaf (e.g.
  `sub-bytes`) → "all port values" shows state-in / round-key / state-out rows;
  "what this step does" shows the SubBytes byte-prose. Select an endpoint pill →
  no expanders. Confirm no page-scroll jank on a big-aux leaf (PortFlowView's
  `PORT_ROW_CELL_CAP` already caps it).
