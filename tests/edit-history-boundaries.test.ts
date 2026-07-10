/**
 * C3 tests for the unified edit-history store's STACK BOUNDARIES (Part C of
 * `docs/plans/toasty-zooming-harp.md`). C2 wired the capture observer; C3 adds
 * the boundary rule that decides which transitions DROP the history vs. keep it:
 *
 *   • selector switch (cipher / cipherMode / padding / algorithm / Load) →
 *     `withBoundaryReset` — suppress the rebuild, drop both stacks (the rebuilt
 *     spec no longer matches any pre-switch snapshot's implicit selectors).
 *   • encrypt↔decrypt mode flip → KEEP (the observer never watches `mode`).
 *   • density flip → suppress the forced position rescale, but KEEP the stack
 *     (a viewer preference, not a canonical rebuild).
 *
 * These drive the REAL observer (installed in a live `createRoot`, edits made
 * OUTSIDE that block so each store write flushes synchronously — the C2 flush
 * model) so the assertions are on END STATE: undo/redo depths after the
 * boundary, plus the absence of any spurious post-switch capture. (Per the C2
 * closeout, the older "clear-after repopulates from a stale prev" hazard was
 * specific to the retired `{defer:true}` observer; the property that matters now
 * is simply the resulting depth, which this suite pins.)
 */

import { __resetCipherForTests } from "@/ui/stores/cipher";
import {
  __editHistoryDepthsForTests,
  __resetEditHistoryForTests,
  installEditHistoryCapture,
  undo,
  withBoundaryReset,
} from "@/ui/stores/edit-history";
import { __resetLayoutsForTests, setNodePosition, useLayoutMap } from "@/ui/stores/layout";
import {
  __resetSpecForTests,
  editStepParams,
  setCipher,
  setMode,
  useSpec,
  useSpecsByMode,
} from "@/ui/stores/spec";
import { __resetViewDensityForTests, setViewDensity } from "@/ui/stores/view-density";
import { createRoot } from "solid-js";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

const depths = () => __editHistoryDepthsForTests();

let disposeObserver = (): void => {};

/** Reset every source store, then install the real observer in a live root. */
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

describe("edit-history stack boundaries (C3) — selector switch clears", () => {
  it("drops both stacks on a cipher switch and captures no spurious entry", () => {
    // Accumulate real history, then cross a selector boundary. The switch's
    // spec rebuild must not land as an undoable entry (suppress), and the prior
    // history is now invalid because the AES-128 snapshot's selectors don't
    // match AES-256 (clear).
    editStepParams("round.1.sub-bytes", { __histTweak: 1 });
    expect(depths()).toEqual({ undo: 1, redo: 0 });

    const beforeSwitch = useSpecsByMode()();
    withBoundaryReset(() => setCipher("aes-256"));

    // The switch happened (spec is now AES-256) AND the history is empty — no
    // spurious post-switch entry survived the suppress-then-clear.
    expect(useSpecsByMode()()).not.toBe(beforeSwitch);
    expect(depths()).toEqual({ undo: 0, redo: 0 });
  });

  it("resumes capturing on the NEW spec (observer prevInput advanced across the boundary)", () => {
    // The boundary suppresses capture but the `on` observer still runs during
    // the switch, so its `prevInput` advances to the post-switch spec. A genuine
    // edit afterwards must capture exactly once, and its undo must restore the
    // POST-switch spec (not bleed back across the cleared boundary).
    withBoundaryReset(() => setCipher("aes-256"));
    const postSwitch = useSpecsByMode()();
    expect(depths()).toEqual({ undo: 0, redo: 0 });

    editStepParams("round.1.sub-bytes", { __histTweak: 7 });
    expect(depths()).toEqual({ undo: 1, redo: 0 });

    undo();
    expect(useSpecsByMode()()).toBe(postSwitch);
    expect(depths()).toEqual({ undo: 0, redo: 1 });
  });
});

describe("edit-history stack boundaries (C3) — density flip keeps, mode flip keeps", () => {
  it("suppresses the density rescale but PRESERVES the undo stack", () => {
    // A pinned position is a normal layout edit (no gesture) → one entry.
    const specId = useSpec()().id;
    setNodePosition(specId, "round.1", 100, 100);
    expect(depths()).toEqual({ undo: 1, redo: 0 });

    // Flipping density from normal (1.0) to compact (0.75) forces
    // `rescaleAllPositions` to rewrite the WHOLE layout map — which the observer
    // would otherwise capture. It is suppressed (0 new entries) but, unlike a
    // selector switch, the density flip is NOT a boundary: the prior edit
    // stays undoable.
    const beforeFlip = useLayoutMap()();
    setViewDensity("compact");
    expect(useLayoutMap()()).not.toBe(beforeFlip); // rescale really ran
    expect(depths()).toEqual({ undo: 1, redo: 0 }); // stack intact, nothing added
  });

  it("keeps the stack across an encrypt↔decrypt mode flip", () => {
    // The observer watches specs/layoutMap, never `mode`; a flip captures
    // nothing and the boundary rule keeps the history. (Complements the
    // "clear" side above — the two directions of the boundary rule.)
    editStepParams("round.1.sub-bytes", { __histTweak: 1 });
    expect(depths()).toEqual({ undo: 1, redo: 0 });

    setMode("decrypt");
    setMode("encrypt");
    expect(depths()).toEqual({ undo: 1, redo: 0 });
  });
});
