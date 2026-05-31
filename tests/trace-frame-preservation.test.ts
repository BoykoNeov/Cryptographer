/**
 * Phase 1 — frame-preservation behavior of the trace store.
 *
 * Re-running the cipher (manually via the Run button or automatically via
 * the debounced spec-edit effect) used to snap the scrubber back to frame
 * 0, throwing away the user's position. The store now preserves focus by
 * stepId across re-runs, falling back to a clamped numeric index when the
 * stepId disappears.
 *
 * These tests are intentionally decoupled from AES specifics: they build
 * minimal Trace objects with hand-rolled frames so the property being
 * tested is the store's behavior, not the cipher's. Universal across
 * ciphers — a future Speck/ChaCha20 trace inherits the same guarantee.
 */

import type { State, Trace, TraceFrame } from "@/core/types";
import {
  __resetTraceForTests,
  getTrace,
  setFrame,
  setTrace,
  useFrameIndex,
} from "@/ui/stores/trace";
import { beforeEach, describe, expect, it } from "vitest";

// Dummy state — frame-preservation logic never inspects it, so a trivial
// bytes payload is enough.
const emptyState = (): State => ({ shape: "bytes", bytes: new Uint8Array(0) });

const makeFrame = (index: number, stepId: string): TraceFrame => ({
  index,
  path: [],
  stepId,
  stepType: "test.noop@1",
  params: null,
  stateBefore: emptyState(),
  stateAfter: emptyState(),
  auxRead: new Map(),
  auxWritten: new Map(),
});

const makeTrace = (stepIds: readonly string[]): Trace => ({
  frames: stepIds.map((id, i) => makeFrame(i, id)),
  initialState: emptyState(),
  finalState: emptyState(),
  finalAux: new Map(),
});

describe("trace store — frame preservation across re-runs", () => {
  beforeEach(() => {
    __resetTraceForTests();
  });

  it("starts at frame 0 on the very first trace (no prior to preserve)", () => {
    const trace = makeTrace(["a", "b", "c"]);
    setTrace(trace);
    expect(useFrameIndex()()).toBe(0);
  });

  it("stays on the same stepId when re-running a trace with the same steps", () => {
    // User runs once, scrubs to step "b".
    setTrace(makeTrace(["a", "b", "c", "d"]));
    setFrame(1);
    expect(useFrameIndex()()).toBe(1);

    // Same shape on re-run (e.g. user edited an unrelated param). Scrubber
    // must stay on "b" — that's the whole point of the feature.
    setTrace(makeTrace(["a", "b", "c", "d"]));
    expect(useFrameIndex()()).toBe(1);
    expect(getTrace()?.frames[useFrameIndex()()]?.stepId).toBe("b");
  });

  it("follows the stepId when re-ordering shifts its numeric position", () => {
    // The user is staring at "sub-bytes" at index 1.
    setTrace(makeTrace(["add-key", "sub-bytes", "shift-rows", "mix-cols"]));
    setFrame(1);

    // A different spec moves sub-bytes to index 3 (e.g. via a reorder).
    // Frame index must follow the stepId, not stay at the old numeric slot.
    setTrace(makeTrace(["add-key", "shift-rows", "mix-cols", "sub-bytes"]));
    expect(useFrameIndex()()).toBe(3);
    expect(getTrace()?.frames[useFrameIndex()()]?.stepId).toBe("sub-bytes");
  });

  it("clamps to the new trace's range when the prior stepId no longer exists", () => {
    // User was on the last step of a 5-frame trace.
    setTrace(makeTrace(["a", "b", "c", "d", "e"]));
    setFrame(4);
    expect(useFrameIndex()()).toBe(4);

    // The next trace has only 3 frames and no "e". Fallback clamps the
    // old index (4) into the new range — capped at length-1 = 2.
    setTrace(makeTrace(["x", "y", "z"]));
    expect(useFrameIndex()()).toBe(2);
  });

  it("uses clamp fallback even when the stepId existed previously but is gone now", () => {
    setTrace(makeTrace(["alpha", "beta", "gamma"]));
    setFrame(1); // beta

    // beta deleted; user-position numerically (1) still valid → stays at 1.
    setTrace(makeTrace(["alpha", "delta", "gamma", "epsilon"]));
    expect(useFrameIndex()()).toBe(1);
    // (Not asserting on stepId — the contract is "clamp the index," not
    // "match a stepId we don't have.")
  });

  it("does not crash when the previous trace was empty", () => {
    // Edge case: a degenerate empty trace, then a real one.
    setTrace({
      frames: [],
      initialState: emptyState(),
      finalState: emptyState(),
      finalAux: new Map(),
    });
    expect(useFrameIndex()()).toBe(0);

    setTrace(makeTrace(["a", "b"]));
    // Prior trace had no frames so previousStepId is undefined and
    // previousIdx clamps to 0.
    expect(useFrameIndex()()).toBe(0);
  });
});
