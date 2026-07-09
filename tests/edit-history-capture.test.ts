/**
 * C2 tests for the unified edit-history store's App-scope capture observer
 * (`installEditHistoryCapture` in `src/ui/stores/edit-history.ts`, Part C of
 * `docs/plans/toasty-zooming-harp.md`). C1 drove `captureTransition` directly;
 * these drive the REAL `createEffect(on([specs, layout]))` — the wiring where
 * the deferred-vs-immediate subtlety lives — by installing the observer in a
 * live `createRoot` and mutating the real spec/layout stores.
 *
 * ─── Why the observer is NOT `{ defer: true }` (the load-bearing property) ───
 *
 * Solid's `on` returns from a deferred initial run BEFORE it records
 * `prevInput` (verified against `solid.cjs`), so with `defer` the FIRST real
 * change fires the callback with `prevInput === undefined` and the observer's
 * `!prev` guard would silently DROP it — the first non-drag edit after a fresh
 * load would not be undoable. Running non-deferred instead lets the immediate
 * init run establish `prevInput` (the `!prev` guard skips that one no-op), so
 * the first genuine edit already carries a correct pre-change snapshot. The
 * FIRST test below is the regression guard for exactly that: it must record
 * depth 1 on the very first edit. (It would read 0 under `defer: true`.)
 *
 * ─── Flush model ────────────────────────────────────────────────────────────
 *
 * Signal writes made INSIDE the `createRoot` synchronous body coalesce (the
 * effect's init run hasn't flushed yet). So the harness installs the observer,
 * lets the root settle (init run fires + is skipped), then performs each edit
 * OUTSIDE that block — where every store write synchronously flushes the
 * observer with the right prev/cur, matching production.
 */

import { getDefaultCollapsedContainers } from "@/core/spec-defaults";
import { __resetCipherForTests } from "@/ui/stores/cipher";
import {
  __editHistoryDepthsForTests,
  __resetEditHistoryForTests,
  beginLayoutGesture,
  endLayoutGesture,
  installEditHistoryCapture,
  redo,
  undo,
} from "@/ui/stores/edit-history";
import {
  __resetLayoutsForTests,
  getLayoutForSpec,
  setNodePosition,
  toggleCollapse,
  useLayoutMap,
} from "@/ui/stores/layout";
import {
  __resetSpecForTests,
  duplicateRoundInSpec,
  editStepParams,
  setMode,
  useSpec,
  useSpecsByMode,
} from "@/ui/stores/spec";
import { createRoot } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const depths = () => __editHistoryDepthsForTests();

let disposeObserver = (): void => {};

/**
 * Reset the stores, then install the real capture observer in a live root and
 * let it settle. After this returns the init run has already fired (and been
 * skipped by the `!prev` guard), so the undo depth is a clean 0 and every
 * subsequent store write flushes the observer exactly as in the app.
 */
const setupWithObserver = (): void => {
  __resetSpecForTests();
  __resetCipherForTests();
  __resetLayoutsForTests();
  __resetEditHistoryForTests();
  createRoot((d) => {
    disposeObserver = d;
    installEditHistoryCapture();
  });
};

beforeEach(setupWithObserver);
afterEach(() => {
  disposeObserver();
  disposeObserver = (): void => {};
  __resetEditHistoryForTests();
});

describe("edit-history capture observer (C2) — spec edits", () => {
  it("records the VERY FIRST non-drag edit (defer-bug regression guard)", () => {
    // If the observer were `{ defer: true }`, this first edit would arrive with
    // `prevInput === undefined` and be dropped → depth 0. Non-deferred, the
    // init run established prevInput, so the first real edit captures.
    const pristine = useSpecsByMode()();

    editStepParams("round.1.sub-bytes", { __histTweak: 1 });
    expect(useSpecsByMode()()).not.toBe(pristine);
    expect(depths()).toEqual({ undo: 1, redo: 0 });

    undo();
    expect(useSpecsByMode()()).toBe(pristine);
    expect(depths()).toEqual({ undo: 0, redo: 1 });

    redo();
    expect(depths()).toEqual({ undo: 1, redo: 0 });
  });

  it("keeps tracking across successive edits (prevInput stays synced)", () => {
    const pristine = useSpecsByMode()();

    editStepParams("round.1.sub-bytes", { __histTweak: 1 });
    const afterFirst = useSpecsByMode()();
    editStepParams("round.1.sub-bytes", { __histTweak: 2 });
    expect(depths()).toEqual({ undo: 2, redo: 0 });

    undo();
    expect(useSpecsByMode()()).toBe(afterFirst);
    undo();
    expect(useSpecsByMode()()).toBe(pristine);
    expect(depths()).toEqual({ undo: 0, redo: 2 });
  });

  it("does NOT capture a bare encrypt↔decrypt mode flip", () => {
    // The observer watches `specs`/`layoutMap`, never `mode`. A mode flip
    // changes neither, so nothing is captured and the stack survives (the
    // stack-boundary rule: mode flips KEEP the history).
    editStepParams("round.1.sub-bytes", { __histTweak: 1 });
    expect(depths()).toEqual({ undo: 1, redo: 0 });

    setMode("decrypt");
    setMode("encrypt");
    expect(depths()).toEqual({ undo: 1, redo: 0 });
  });
});

describe("edit-history capture observer (C2) — atomic + coalesced mutations", () => {
  it("captures a duplicate-round as exactly ONE entry (batch), reverting both slots", () => {
    // `duplicateRoundInSpec` performs three signal writes (setSpecs + two
    // layout renames) inside a single `batch()`. Without the batch the
    // deferred observer would fire up to three times = three undo entries.
    const pristine = useSpecsByMode()();

    duplicateRoundInSpec("round.1");
    expect(useSpecsByMode()()).not.toBe(pristine);
    expect(depths()).toEqual({ undo: 1, redo: 0 });

    undo();
    expect(useSpecsByMode()()).toBe(pristine);
    expect(depths()).toEqual({ undo: 0, redo: 1 });
  });

  it("captures a collapse toggle (guard-3 false branch: layout change, no gesture) as ONE entry", () => {
    // A `toggleCollapse` changes the layout map with specs unchanged AND no
    // drag gesture active — the ONE normal-edit class that lands in guard 3's
    // FALSE branch (`layoutGestureActive` is false, so it does NOT coalesce).
    // Per the stack-boundary rule, collapse/replication toggles are undoable
    // per-spec layout edits: one entry each. Guards against a future
    // "simplify" of the gesture-flag logic silently swallowing them.
    const spec = useSpec()();
    const specId = spec.id;
    const containerId = "round.1";
    const inDefaults = getDefaultCollapsedContainers(spec).has(containerId);
    const before = useLayoutMap()();

    toggleCollapse(specId, containerId, inDefaults);
    expect(useLayoutMap()()).not.toBe(before);
    expect(depths().undo).toBe(1);

    undo();
    expect(useLayoutMap()()).toBe(before);
    expect(depths()).toEqual({ undo: 0, redo: 1 });
  });

  it("coalesces a drag into ONE entry through the live observer", () => {
    const specId = useSpec()().id;
    const preDragLayout = useLayoutMap()();

    // Each `setNodePosition` below flushes the observer; while the gesture is
    // active and specs are unchanged, guard 3 skips every one of them. The
    // single pre-drag entry is committed by `endLayoutGesture`.
    beginLayoutGesture();
    for (let i = 1; i <= 3; i++) setNodePosition(specId, "round.1", i * 10, i * 10);
    expect(depths().undo).toBe(0);

    endLayoutGesture();
    expect(depths().undo).toBe(1);

    undo();
    expect(useLayoutMap()()).toBe(preDragLayout);
    expect(getLayoutForSpec(specId)).toBeNull();
  });
});

describe("edit-history capture observer (C2) — re-entrancy", () => {
  it("does not re-capture the observer's own undo/redo restore writes", () => {
    editStepParams("round.1.sub-bytes", { __histTweak: 1 });
    expect(depths()).toEqual({ undo: 1, redo: 0 });

    // `undo` writes the restored refs through the SAME batch the observer
    // watches; the reference-identity `lastApplied` guard must skip that write
    // rather than pushing a spurious entry (which would create an undo loop).
    undo();
    expect(depths()).toEqual({ undo: 0, redo: 1 });

    redo();
    expect(depths()).toEqual({ undo: 1, redo: 0 });

    undo();
    expect(depths()).toEqual({ undo: 0, redo: 1 });
  });
});
