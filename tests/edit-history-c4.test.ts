/**
 * C4 tests for the unified edit-history store (Part C of
 * `docs/plans/toasty-zooming-harp.md`). C4 makes undo/redo user-reachable
 * (toolbar + shortcuts); these node-env tests pin the two capture-side C4
 * behaviors that don't need a DOM:
 *
 *   • `resetSpec` (a spec rebuild WITHOUT a selector change) flows as ONE
 *     ordinary undoable edit — advisor item 5. It's a single `updateActive`
 *     write, so it must land exactly one entry (not several like an unbatched
 *     multi-write would).
 *   • `cancelLayoutGesture` unsticks a leaked drag-gesture flag — the C4
 *     hardening for the lost-`pointerup` edge. A stuck `layoutGestureActive`
 *     coalesces away the next pure-layout edit (guard 3); the discrete op calls
 *     `cancelLayoutGesture` first so its own write survives.
 *
 * Same live-observer harness as the C2/C3 suites: install the REAL observer in
 * a `createRoot`, make edits OUTSIDE it so each store write flushes
 * synchronously (the C2 flush model), assert on end-state depths.
 */

import { __resetCipherForTests } from "@/ui/stores/cipher";
import {
  __editHistoryDepthsForTests,
  __resetEditHistoryForTests,
  beginLayoutGesture,
  cancelLayoutGesture,
  installEditHistoryCapture,
  undo,
} from "@/ui/stores/edit-history";
import { __resetLayoutsForTests, setNodePosition, useLayoutMap } from "@/ui/stores/layout";
import {
  __resetSpecForTests,
  editStepParams,
  resetSpec,
  useSpec,
  useSpecsByMode,
} from "@/ui/stores/spec";
import { __resetViewDensityForTests } from "@/ui/stores/view-density";
import { createRoot } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const depths = () => __editHistoryDepthsForTests();

let disposeObserver = (): void => {};

const setupWithObserver = (): void => {
  __resetSpecForTests();
  __resetCipherForTests();
  __resetLayoutsForTests();
  __resetViewDensityForTests();
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
  __resetViewDensityForTests();
  __resetEditHistoryForTests();
});

describe("edit-history C4 — resetSpec is one ordinary undoable edit (item 5)", () => {
  it("captures exactly ONE entry and its undo restores the pre-reset spec", () => {
    // Edit a param so the active spec diverges from canonical (1 entry).
    editStepParams("round.1.sub-bytes", { __histTweak: 1 });
    expect(depths()).toEqual({ undo: 1, redo: 0 });
    const custom = useSpecsByMode()();

    // A spec rebuild WITHOUT a selector change (resetSpec restores the
    // canonical spec for the current mode) is NOT a boundary — it flows as an
    // ordinary edit. It's a single `updateActive` write, so exactly one entry.
    resetSpec();
    expect(depths()).toEqual({ undo: 2, redo: 0 });
    expect(useSpecsByMode()()).not.toBe(custom);

    // Undo the reset → back to the custom spec (proves it was one atomic entry,
    // not several partial ones).
    undo();
    expect(useSpecsByMode()()).toBe(custom);
    expect(depths()).toEqual({ undo: 1, redo: 1 });
  });
});

describe("edit-history C4 — cancelLayoutGesture unsticks a leaked drag flag", () => {
  it("a stuck gesture coalesces away the next layout edit until cancel clears it", () => {
    const specId = useSpec()().id;

    // Simulate a drag whose `pointerup` was lost: the gesture opens but
    // `endLayoutGesture` never runs, so `layoutGestureActive` stays true.
    beginLayoutGesture();

    // The HAZARD: with the flag stuck, a discrete pure-layout edit is dropped
    // by guard 3 (`layoutGestureActive && prev.specs === cur.specs`).
    setNodePosition(specId, "round.1", 50, 50);
    expect(depths()).toEqual({ undo: 0, redo: 0 });

    // The FIX: the discrete op calls `cancelLayoutGesture` first — flag cleared,
    // nothing committed. Its own write then captures normally.
    cancelLayoutGesture();
    setNodePosition(specId, "round.1", 120, 120);
    expect(depths()).toEqual({ undo: 1, redo: 0 });

    // And the entry is real — undo reverts the position edit's whole map.
    const afterEdit = useLayoutMap()();
    undo();
    expect(useLayoutMap()()).not.toBe(afterEdit);
    expect(depths()).toEqual({ undo: 0, redo: 1 });
  });
});
