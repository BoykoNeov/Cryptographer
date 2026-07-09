/**
 * Unified edit-history store (Part C of the graph-legibility plan,
 * `docs/plans/toasty-zooming-harp.md`). ONE undo/redo stack spanning BOTH
 * spec edits (param, rewire, palette/composite drop, delete, duplicate-round,
 * cross-mode mirrors) AND layout moves (drag, collapse, replication mode,
 * reset). Distinct from the RUN-history store in `history.ts` (that one
 * records trace snapshots for the RunExplorer; this one records editable
 * state for undo/redo).
 *
 * ─── Design (snapshot-based, all state owned here) ───────────────────────
 *
 * A snapshot captures the WHOLE dual-mode spec union + the WHOLE layout map,
 * both **by reference — O(1)**. This is sound because neither store ever
 * mutates in place: the spec store rebuilds `SpecsByMode` with structural
 * sharing (ref-equality early-return on untouched branches) and the layout
 * store replaces `layoutMap` wholesale on every setter. A captured reference
 * therefore stays a valid, immutable past state forever.
 *
 * Two undo/redo stacks (`undoStack` holds past pre-change states, `redoStack`
 * holds undone future states), each a ring buffer capped at `MAX_UNDO`.
 * Both are signals so the C4 toolbar's `useCanUndo()` / `useCanRedo()` depth
 * accessors are reactive.
 *
 * The rest of the history state is plain (non-reactive) module control state:
 *   • `lastApplied`         — re-entrancy guard: the {specs, layout} refs the
 *                             apply path last wrote, so the (deferred) capture
 *                             observer can skip the restore's OWN write by
 *                             reference identity (timing-immune, unlike a
 *                             boolean+microtask flag).
 *   • `suppressCapture`     — set around selector-boundary writes (C3) so the
 *                             observer ignores a canonical rebuild.
 *   • `layoutGestureActive` — set for the duration of a drag so per-pointermove
 *                             pure-layout changes coalesce into ONE entry.
 *   • `gestureSnapshot`     — the pre-drag snapshot captured at gesture start.
 *
 * ─── Capture / apply split (why C2 is pure wiring) ───────────────────────
 *
 * The capture entry point `captureTransition(prev, cur)` takes an EXPLICIT
 * pre-change snapshot. In C2 the App-scope `createEffect(on([specs, layout],
 * …, {defer:true}))` just forwards Solid's `prev`/`cur` here; the store's
 * internals never change. C1 tests drive `captureTransition` directly with no
 * observer at all.
 *
 * The apply path (`undo`/`redo`) sets `lastApplied` to the target snapshot's
 * refs BEFORE writing, then restores specs + layout inside one Solid
 * `batch()` so subscribers see a single atomic (spec, layout) transition and
 * the 200ms debounced rerun fires once. Traces are NEVER stored in snapshots
 * — the rerun regenerates the trace and `setTrace` preserves the frame by
 * stepId.
 */

import { batch, createEffect, createSignal, on } from "solid-js";
import { type LayoutMap, replaceLayoutMap, useLayoutMap } from "./layout";
import {
  type Mode,
  type SpecsByMode,
  restoreSpecsForHistory,
  useMode,
  useSpecsByMode,
} from "./spec";

/**
 * Largest number of undo steps retained. Run-history's 5 is far too shallow
 * for an editing session — 50 covers a long rearrange-and-rewire session
 * without unbounded memory growth (each entry is two references).
 */
export const MAX_UNDO = 50;

/**
 * One editable-state snapshot. `mode` is captured but NOT force-restored on
 * undo (view-stable undo): restoring the whole `specs` union reverts whichever
 * slot the edit touched regardless of which side the user is currently
 * viewing, so there's no need to yank the mode selector around under them.
 */
export type EditSnapshot = {
  readonly specs: SpecsByMode;
  readonly layoutMap: LayoutMap;
  readonly mode: Mode;
};

/** A (specs, layout) reference pair — the observer's re-entrancy comparison key. */
type AppliedRefs = {
  readonly specs: SpecsByMode;
  readonly layout: LayoutMap;
};

// ─── State ──────────────────────────────────────────────────────────────

const [undoStack, setUndoStack] = createSignal<readonly EditSnapshot[]>([]);
const [redoStack, setRedoStack] = createSignal<readonly EditSnapshot[]>([]);

/**
 * The {specs, layout} references the apply path last wrote. The capture
 * observer compares the current state against this by reference: if they
 * match, the transition IS the restore's own write, so skip it. Reset to
 * null once a genuine (non-restore) edit is captured — real edits always
 * mint new references, so the guard never false-skips.
 */
let lastApplied: AppliedRefs | null = null;

/** When true, the capture observer ignores transitions (selector boundaries). */
let suppressCapture = false;

/** When true, a drag is in progress and pure-layout changes coalesce. */
let layoutGestureActive = false;

/** Pre-drag snapshot recorded at gesture start; pushed once on gesture end. */
let gestureSnapshot: EditSnapshot | null = null;

// ─── Reads (C4 toolbar) ───────────────────────────────────────────────────

export const useCanUndo = () => (): boolean => undoStack().length > 0;
export const useCanRedo = () => (): boolean => redoStack().length > 0;

/** Current live editable state as a snapshot. Reads the two source stores. */
const currentSnapshot = (): EditSnapshot => ({
  specs: useSpecsByMode()(),
  layoutMap: useLayoutMap()(),
  mode: useMode()(),
});

// ─── Capture ──────────────────────────────────────────────────────────────

/**
 * Push a pre-change snapshot onto the undo stack, clearing the redo stack
 * (a new edit invalidates any redo future) and evicting the oldest entry
 * past `MAX_UNDO`. Clears the re-entrancy guard — a captured edit is by
 * definition not a restore, so the guard has no more restore to protect.
 */
const pushUndo = (snap: EditSnapshot): void => {
  const next = [...undoStack(), snap];
  if (next.length > MAX_UNDO) next.shift();
  setUndoStack(next);
  setRedoStack([]);
  lastApplied = null;
};

/**
 * Capture entry point. `prev` is the state BEFORE the mutation, `cur` the
 * state after (Solid's `on` prev/cur in C2; supplied explicitly in C1 tests).
 * Applies three guards, then records `prev` as an undo step:
 *
 *   1. `suppressCapture` — selector-boundary write; ignore entirely (C3).
 *   2. Re-entrancy — `cur` matches the last apply's refs → this transition is
 *      the restore's own write; skip. Reference identity, so timing-immune.
 *   3. Active drag + pure-layout change (`prev.specs === cur.specs`) — a
 *      per-pointermove tick; the gesture coalesces these into one entry
 *      pushed by `endLayoutGesture`, so skip here.
 */
export const captureTransition = (
  prev: { readonly specs: SpecsByMode; readonly layout: LayoutMap },
  cur: { readonly specs: SpecsByMode; readonly layout: LayoutMap },
): void => {
  if (suppressCapture) return;
  if (lastApplied && cur.specs === lastApplied.specs && cur.layout === lastApplied.layout) {
    return;
  }
  if (layoutGestureActive && prev.specs === cur.specs) return;
  pushUndo({ specs: prev.specs, layoutMap: prev.layout, mode: useMode()() });
};

// ─── Observer wiring (C2) ───────────────────────────────────────────────────

/**
 * Install the App-scope capture observer: ONE `createEffect(on(...))` watching
 * the whole dual-mode spec union AND the whole layout map, so every mutation to
 * either store flows through a single place and forwards its (pre-change,
 * post-change) snapshot pair to `captureTransition`. Mirrors
 * `installKeyboardShortcuts()` — called once from App scope, so it lives as long
 * as the app does. C1 tests drove `captureTransition` directly; C2 tests drive
 * this real observer.
 *
 * **Deliberately NOT `{ defer: true }`** — despite the plan's wording. Solid's
 * `on` returns from a deferred initial run BEFORE it records `prevInput`
 * (verified in `solid.cjs`: the `if (defer) { defer = false; return prevValue }`
 * branch short-circuits ahead of `prevInput = input`). So with `defer`, the
 * FIRST real change fires `fn` with `prevInput === undefined` and the `!prev`
 * guard would silently drop it — the first non-drag edit after a fresh load
 * would not be undoable, throwing every later undo depth off by one. Running
 * non-deferred instead means the immediate init run fires `fn(input, undefined)`
 * — the `!prev` guard skips that one no-op — and `on` then sets `prevInput =
 * input`, so the first GENUINE change already carries the correct pre-change
 * snapshot. (The drag path masks this bug because `endLayoutGesture` pushes its
 * snapshot directly, not through this observer; only a non-drag first edit
 * exposes it.)
 *
 * Reads BOTH deps every run (unconditional array read) — a conditional dep read
 * would desync `on`'s `prevInput` and corrupt the next entry.
 */
export const installEditHistoryCapture = (): void => {
  createEffect(
    on([useSpecsByMode(), useLayoutMap()], ([curSpecs, curLayout], prev) => {
      if (!prev) return; // init run: only establishes prevInput, captures nothing
      captureTransition(
        { specs: prev[0], layout: prev[1] },
        { specs: curSpecs, layout: curLayout },
      );
    }),
  );
};

// ─── Apply (undo / redo) ────────────────────────────────────────────────────

/**
 * Restore a snapshot into the live stores. Sets the re-entrancy guard to the
 * target's refs FIRST (so the deferred capture observer skips this write),
 * then writes specs + layout inside one `batch()` for a single atomic
 * transition. Mode is intentionally NOT restored (view-stable undo).
 */
const applySnapshot = (snap: EditSnapshot): void => {
  lastApplied = { specs: snap.specs, layout: snap.layoutMap };
  batch(() => {
    restoreSpecsForHistory(snap.specs);
    replaceLayoutMap(snap.layoutMap);
  });
};

/**
 * Undo the most recent edit. Pushes the CURRENT state onto the redo stack,
 * then restores the popped past snapshot. No-op when the undo stack is empty.
 */
export const undo = (): void => {
  const stack = undoStack();
  if (stack.length === 0) return;
  const target = stack[stack.length - 1];
  if (!target) return;
  const current = currentSnapshot();
  setUndoStack(stack.slice(0, -1));
  setRedoStack([...redoStack(), current]);
  applySnapshot(target);
};

/**
 * Redo the most recently undone edit. Pushes the CURRENT state back onto the
 * undo stack, then restores the popped future snapshot. No-op when the redo
 * stack is empty.
 */
export const redo = (): void => {
  const stack = redoStack();
  if (stack.length === 0) return;
  const target = stack[stack.length - 1];
  if (!target) return;
  const current = currentSnapshot();
  setRedoStack(stack.slice(0, -1));
  setUndoStack([...undoStack(), current]);
  applySnapshot(target);
};

// ─── Drag coalescing (functions live here; wired from GraphView in C2) ──────

/**
 * Mark the start of a layout drag. Records the pre-drag snapshot and sets the
 * gesture flag so the observer coalesces the per-pointermove layout writes.
 * The single pre-drag entry is committed by `endLayoutGesture` iff the drag
 * actually changed the layout map.
 */
export const beginLayoutGesture = (): void => {
  gestureSnapshot = currentSnapshot();
  layoutGestureActive = true;
};

/**
 * Mark the end of a layout drag. Commits ONE undo entry (the pre-drag
 * snapshot) iff the layout map reference actually changed during the drag —
 * a sub-threshold click that never moved anything leaves the map reference
 * untouched and records nothing. Idempotent when no gesture is active.
 */
export const endLayoutGesture = (): void => {
  if (!layoutGestureActive) return;
  layoutGestureActive = false;
  const before = gestureSnapshot;
  gestureSnapshot = null;
  if (!before) return;
  // Reference identity: a real drag replaced the layout map wholesale; a
  // sub-threshold click left it untouched.
  if (useLayoutMap()() === before.layoutMap) return;
  pushUndo(before);
};

// ─── Boundary suppression + clear (orchestration finalized in C3) ───────────

/**
 * Run `fn` with capture suppressed. Selector-driven canonical rebuilds
 * (cipher / cipherMode / padding / category switch, Load) go through here so
 * the observer doesn't record the rebuild as an undoable edit. Restores the
 * prior flag value on exit (nestable). C3 wires the call sites + pairs this
 * with `clearEditHistory` per the stack-boundary rule.
 */
export const withCaptureSuppressed = (fn: () => void): void => {
  const prev = suppressCapture;
  suppressCapture = true;
  try {
    fn();
  } finally {
    suppressCapture = prev;
  }
};

/** Drop both stacks (selector-boundary reset). Leaves live store state alone. */
export const clearEditHistory = (): void => {
  setUndoStack([]);
  setRedoStack([]);
  lastApplied = null;
};

/** Test-only stack depths (production reads booleans via useCanUndo/useCanRedo). */
export const __editHistoryDepthsForTests = (): {
  readonly undo: number;
  readonly redo: number;
} => ({
  undo: undoStack().length,
  redo: redoStack().length,
});

/** Hard reset for tests. Production code uses `clearEditHistory`. */
export const __resetEditHistoryForTests = (): void => {
  setUndoStack([]);
  setRedoStack([]);
  lastApplied = null;
  suppressCapture = false;
  layoutGestureActive = false;
  gestureSnapshot = null;
};
