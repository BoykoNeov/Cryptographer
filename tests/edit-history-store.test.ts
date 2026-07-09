/**
 * C1 tests for the unified edit-history store (`src/ui/stores/edit-history.ts`,
 * Part C of `docs/plans/toasty-zooming-harp.md`). This chunk ships the store
 * + its two apply setters (`restoreSpecsForHistory`, `replaceLayoutMap`) with
 * NO observer wired — so every test drives the real spec/layout setters and
 * calls `captureTransition` explicitly, exactly as the C2 App-scope observer
 * will forward Solid's prev/cur.
 *
 * The load-bearing property throughout: snapshots are captured BY REFERENCE
 * and restored by reference. Both source stores rebuild their state wholesale
 * (structural sharing on untouched branches), so `undo()` landing the exact
 * pre-edit reference (`toBe`, not `toEqual`) proves the O(1)-snapshot design
 * is sound.
 *
 * Property bundles:
 *   1. Spec edit → undo restores the prior spec REFERENCE; redo re-applies.
 *   2. Layout drag position → undo/redo restore the whole layout map.
 *   3. A fresh capture clears the redo stack (redo-invalidation).
 *   4. undo/redo are no-ops on empty stacks.
 *   5. The undo stack is a ring buffer capped at MAX_UNDO.
 *   6. `withCaptureSuppressed` ignores the transition (C3 primitive).
 *   7. `clearEditHistory` drops both stacks.
 *   8. Re-entrancy: a transition whose `cur` matches the last apply's refs is
 *      skipped (the timing-immune guard the C2 observer depends on).
 *   9. Drag coalescing: begin→pumps→end = exactly ONE entry; a sub-threshold
 *      click (begin→end, no move) = ZERO entries.
 */

import { __resetCipherForTests } from "@/ui/stores/cipher";
import {
  MAX_UNDO,
  __editHistoryDepthsForTests,
  __resetEditHistoryForTests,
  beginLayoutGesture,
  captureTransition,
  clearEditHistory,
  endLayoutGesture,
  redo,
  undo,
  withCaptureSuppressed,
} from "@/ui/stores/edit-history";
import {
  __resetLayoutsForTests,
  getLayoutForSpec,
  setNodePosition,
  useLayoutMap,
} from "@/ui/stores/layout";
import { __resetSpecForTests, editStepParams, useSpec, useSpecsByMode } from "@/ui/stores/spec";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const resetAll = (): void => {
  __resetSpecForTests();
  __resetCipherForTests();
  __resetLayoutsForTests();
  __resetEditHistoryForTests();
};

/** Snapshot the two source stores' current references. */
const refs = () => ({ specs: useSpecsByMode()(), layout: useLayoutMap()() });

/** Run `mutate`, then capture the pre→post transition (what the C2 observer does). */
const withCapture = (mutate: () => void): void => {
  const prev = refs();
  mutate();
  captureTransition(prev, refs());
};

const depths = () => __editHistoryDepthsForTests();

beforeEach(resetAll);
afterEach(resetAll);

describe("edit-history store (C1) — spec edits", () => {
  it("undo restores the prior spec reference and redo re-applies it", () => {
    const specsA = useSpecsByMode()();

    withCapture(() => editStepParams("round.1.sub-bytes", { __histTweak: 1 }));
    const specsB = useSpecsByMode()();
    expect(specsB).not.toBe(specsA);
    expect(depths()).toEqual({ undo: 1, redo: 0 });

    undo();
    expect(useSpecsByMode()()).toBe(specsA);
    expect(depths()).toEqual({ undo: 0, redo: 1 });

    redo();
    expect(useSpecsByMode()()).toBe(specsB);
    expect(depths()).toEqual({ undo: 1, redo: 0 });
  });

  it("a fresh capture after an undo clears the redo stack", () => {
    withCapture(() => editStepParams("round.1.sub-bytes", { __histTweak: 1 }));
    undo();
    expect(depths()).toEqual({ undo: 0, redo: 1 });

    withCapture(() => editStepParams("round.1.sub-bytes", { __histTweak: 2 }));
    expect(depths()).toEqual({ undo: 1, redo: 0 });
  });
});

describe("edit-history store (C1) — layout moves", () => {
  it("undo/redo restore the whole layout map across a drag position", () => {
    const specId = useSpec()().id;
    expect(getLayoutForSpec(specId)).toBeNull();

    withCapture(() => setNodePosition(specId, "round.1", 100, 200));
    expect(getLayoutForSpec(specId)?.positions["round.1"]).toEqual({ x: 100, y: 200 });

    undo();
    expect(getLayoutForSpec(specId)).toBeNull();

    redo();
    expect(getLayoutForSpec(specId)?.positions["round.1"]).toEqual({ x: 100, y: 200 });
  });
});

describe("edit-history store (C1) — stack discipline", () => {
  it("undo and redo are no-ops on empty stacks", () => {
    expect(() => {
      undo();
      redo();
    }).not.toThrow();
    expect(depths()).toEqual({ undo: 0, redo: 0 });
  });

  it("caps the undo stack at MAX_UNDO (ring buffer eviction)", () => {
    const specId = useSpec()().id;
    for (let i = 0; i < MAX_UNDO + 5; i++) {
      withCapture(() => setNodePosition(specId, "round.1", i, i));
    }
    expect(depths().undo).toBe(MAX_UNDO);
  });

  it("clearEditHistory drops both stacks", () => {
    withCapture(() => editStepParams("round.1.sub-bytes", { __histTweak: 1 }));
    undo();
    expect(depths()).toEqual({ undo: 0, redo: 1 });

    clearEditHistory();
    expect(depths()).toEqual({ undo: 0, redo: 0 });
  });
});

describe("edit-history store (C1) — guards", () => {
  it("withCaptureSuppressed ignores the transition", () => {
    withCaptureSuppressed(() => {
      withCapture(() => editStepParams("round.1.sub-bytes", { __histTweak: 1 }));
    });
    expect(depths()).toEqual({ undo: 0, redo: 0 });
  });

  it("re-entrancy: a transition matching the last apply's refs is skipped", () => {
    // Build one edit, then undo it. `undo` sets the internal `lastApplied`
    // guard to the restored (specs, layout) refs — this is what the C2
    // observer's own restore write must NOT re-capture.
    withCapture(() => editStepParams("round.1.sub-bytes", { __histTweak: 1 }));
    undo();
    expect(depths()).toEqual({ undo: 0, redo: 1 });

    // Simulate the deferred observer firing on the restore's own write: `cur`
    // equals the freshly-restored live refs. It must be skipped, not captured.
    captureTransition({ specs: useSpecsByMode()(), layout: useLayoutMap()() }, refs());
    expect(depths()).toEqual({ undo: 0, redo: 1 });
  });
});

describe("edit-history store (C1) — drag coalescing", () => {
  it("begin → pumps → end records exactly one undo entry", () => {
    const specId = useSpec()().id;
    const preDragLayout = useLayoutMap()();

    beginLayoutGesture();
    // Each pointermove writes the layout and the observer would call
    // captureTransition; while the gesture is active + specs unchanged, every
    // one of these is coalesced away.
    for (let i = 1; i <= 3; i++) {
      const prev = refs();
      setNodePosition(specId, "round.1", i * 10, i * 10);
      captureTransition(prev, refs());
    }
    expect(depths().undo).toBe(0);

    endLayoutGesture();
    expect(depths().undo).toBe(1);

    undo();
    expect(useLayoutMap()()).toBe(preDragLayout);
    expect(getLayoutForSpec(specId)).toBeNull();
  });

  it("a sub-threshold click (begin → end, no move) records zero entries", () => {
    beginLayoutGesture();
    endLayoutGesture();
    expect(depths().undo).toBe(0);
  });
});
