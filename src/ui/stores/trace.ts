import type { Trace } from "@/core/types";
import { createSignal } from "solid-js";

/**
 * The trace itself lives outside the reactive system — only the index is
 * reactive. A 50,000-frame trace inside a Solid store would tank perf.
 */
let currentTrace: Trace | null = null;

const [frameIndex, setFrameIndex] = createSignal(0);
const [version, setVersion] = createSignal(0);

/**
 * Which step the editor surface (ParamEditor) is currently bound to. Lives
 * alongside `frameIndex` because the two are semantically paired: scrubbing
 * to a new frame and clicking a leaf in the graph view should both update
 * the editor's focus.
 *
 * Why a separate signal instead of `currentFrame()?.stepId`: a step the
 * user JUST inserted (palette drop) has no trace frame yet for the first
 * 200ms of debounced rerun, and a step inserted after an upstream error
 * may NEVER get a frame. The editor must still be clickable in both cases.
 * The signal-vs-derived split lets us keep selection valid even when no
 * frame backs it.
 *
 * Sync invariants (enforced by `setFrame` + `setTrace` below + `setSelectedStepId`):
 *  - `setFrame(n)` writes `selectedStepId` to frame n's canonical stepId
 *    (`:b{i}` suffix stripped), so linear-view scrubbing keeps the editor
 *    in sync without touching every setFrame call-site.
 *  - `setTrace(...)` writes `selectedStepId` to the landed frame's stepId
 *    so the editor has a sensible target on app boot AND across re-runs.
 *  - `setSelectedStepId(id)` writes the signal directly AND, if `id`
 *    matches a frame in the current trace, also moves the scrubber there.
 *    That makes graph leaf clicks move the linear-view scrubber as a side
 *    effect, matching pre-fix behavior where the trace and editor were
 *    glued through `currentFrame()`.
 */
const [selectedStepId, setSelectedStepIdSignal] = createSignal<string | null>(null);

/**
 * Strip the `:b{i}` block suffix iterate-body frames carry, returning the
 * canonical stepId that lives in the spec. Used by every place we need to
 * convert a trace-frame stepId into "what does the user-visible spec call
 * this step?" — graph leaf click, scrubber sync, and the inverse lookup
 * for `setSelectedStepId` finding a frame index.
 */
const canonicalStepId = (frameStepId: string): string => {
  const colonIdx = frameStepId.indexOf(":b");
  return colonIdx >= 0 ? frameStepId.slice(0, colonIdx) : frameStepId;
};

/**
 * Swap in a new trace. Preserves the user's *focus* across re-runs: if the
 * step you were looking at exists in the new trace (matched by stepId), the
 * scrubber lands on it. Otherwise we clamp the previous numeric index into
 * the new trace's range, and only fall back to 0 if there was no prior
 * trace at all.
 *
 * Why stepId-first: the whole point of the editor is "edit a param, watch
 * how THIS byte changed." Snapping back to frame 0 every re-run forced the
 * user to scrub forward again every time — defeating the loop. Lookup is
 * by stepId (not raw index) so insertion/removal of unrelated steps doesn't
 * pull the focus off the byte you were inspecting. Index-clamp is the
 * safety net for the case where the stepId itself disappeared (deleted or
 * renamed by a spec edit).
 *
 * Universal across ciphers — every cipher's trace runs through this same
 * boundary, so a future Speck/ChaCha20/RSA inherits the behavior for free.
 */
export const setTrace = (trace: Trace) => {
  const previousStepId = currentTrace?.frames[frameIndex()]?.stepId;
  const previousIdx = frameIndex();
  const hadPriorTrace = currentTrace !== null;
  // Read the user's explicit editor selection BEFORE we swap in the new
  // trace. This is the anchor we prefer over the scrubber's previous
  // frame stepId — see the long comment below for why.
  const previousSelectedStepId = selectedStepId();

  currentTrace = trace;

  // Anchor priority for the scrubber lookup:
  //
  //   1. Explicit selection (`previousSelectedStepId`). The user told us
  //      what step they care about by clicking it in the graph view — and
  //      crucially, that step may have NO frame in the previous trace
  //      (palette drop with empty params, or downstream of an upstream
  //      throw). The scrubber's frame index wouldn't have moved in those
  //      cases, so using `previousStepId` here would silently snap focus
  //      back to whatever happened to be at the un-moved frame index.
  //
  //   2. Previous frame stepId (`previousStepId`). Covers the case where
  //      the user has never explicitly clicked a leaf — they've only
  //      scrubbed — and `selectedStepId` either equals the scrubber's
  //      target (kept in sync by setFrame) or is null (very-early boot).
  //      Either way this fallback agrees with the explicit-selection
  //      branch when both are set.
  //
  //   3. Numeric index clamp. Safety net when both stepId lookups fail —
  //      the user's step was renamed or removed by the spec edit. The
  //      ParamEditor's own `findStep` handles the renamed/removed case by
  //      showing the "no step selected" fallback, so this branch is just
  //      keeping the scrubber inside the new trace's range.
  let nextIdx = 0;
  // Tracks whether the explicit-selection branch found the user's anchor
  // in the new trace. If it didn't (or no explicit selection existed),
  // we fall through to repointing `selectedStepId` at the landed frame
  // below — otherwise a cipher swap would leave the editor stuck on a
  // stepId that doesn't exist in the new spec.
  let selectedSurvived = false;
  if (hadPriorTrace && trace.frames.length > 0) {
    if (previousSelectedStepId !== null) {
      const found = trace.frames.findIndex(
        (f) => canonicalStepId(f.stepId) === previousSelectedStepId,
      );
      if (found >= 0) {
        nextIdx = found;
        selectedSurvived = true;
      } else {
        // The user's anchor is gone (deleted, or the cipher was swapped
        // out from under it). Clamp to keep the scrubber inside range;
        // the selection-write block below will repoint the editor to
        // whatever step lives at the new index.
        nextIdx = Math.min(previousIdx, trace.frames.length - 1);
      }
    } else if (previousStepId !== undefined) {
      const found = trace.frames.findIndex((f) => f.stepId === previousStepId);
      nextIdx = found >= 0 ? found : Math.min(previousIdx, trace.frames.length - 1);
    } else {
      nextIdx = Math.min(previousIdx, trace.frames.length - 1);
    }
  }

  const clampedIdx = Math.max(0, nextIdx);
  setFrameIndex(clampedIdx);
  // Selection write policy:
  //
  //   - If the user has an explicit selection AND it survived into the
  //     new trace, DO NOT clobber it. The user clicked aux-xor-1 (which
  //     had no frame); the rerun is trying to "preserve focus" but the
  //     only honest definition of focus is the user's own selection.
  //     Overwriting it produced the bug the advisor caught: 200ms after
  //     a palette drop, the editor would silently flip back to the
  //     previous scrubber target.
  //
  //   - If the selection is null (very-early boot) OR the user's anchor
  //     no longer exists in the new spec (cipher swap, step removed),
  //     reinitialize from the landed frame so the ParamEditor has a
  //     sensible target.
  if (!selectedSurvived) {
    const landedFrame = trace.frames[clampedIdx];
    if (landedFrame) {
      setSelectedStepIdSignal(canonicalStepId(landedFrame.stepId));
    }
  }
  setVersion((v) => v + 1);
};

/**
 * Reset back to first-run state. Used by tests; production code never calls
 * this. Exists so the stepId-preservation test can simulate "no prior trace"
 * between test cases without the test file having to reach into module state.
 */
export const __resetTraceForTests = () => {
  currentTrace = null;
  setFrameIndex(0);
  setVersion(0);
  setSelectedStepIdSignal(null);
};

export const getTrace = (): Trace | null => currentTrace;

export const useFrameIndex = () => frameIndex;
export const setFrame = (n: number) => {
  if (!currentTrace) return;
  const max = currentTrace.frames.length - 1;
  const clamped = Math.max(0, Math.min(n, max));
  setFrameIndex(clamped);
  // Move the editor's selection alongside the scrubber. Linear-view
  // scrubbing (keyboard, timeline, neighborhood strip) all funnel through
  // here, so this single line keeps ParamEditor in sync with all of them.
  const frame = currentTrace.frames[clamped];
  if (frame) setSelectedStepIdSignal(canonicalStepId(frame.stepId));
};

/** Bumps when the trace is replaced. Read this in createMemo to invalidate views. */
export const useTraceVersion = () => version;

/**
 * Read the currently selected step id. ParamEditor mounts call this to
 * resolve the live spec leaf they should render an editor for.
 */
export const useSelectedStepId = () => selectedStepId;

/**
 * Move the editor's focus to a specific step. Two effects:
 *  1. Always updates the `selectedStepId` signal — the ParamEditor will
 *     re-resolve and render the new step regardless of trace state. This
 *     is the bug-2 fix: a freshly-dropped step with no executed frame is
 *     still editable because the params live on the spec, not the frame.
 *  2. If `id` matches a frame in the current trace, also moves the
 *     scrubber there. The lookup tolerates `:b{i}`-suffixed frame ids by
 *     stripping the suffix before comparing — graph clicks on iterate-body
 *     leaves land on the first block's frame, matching the prior behavior.
 */
export const setSelectedStepId = (id: string | null): void => {
  setSelectedStepIdSignal(id);
  if (id === null || !currentTrace) return;
  const idx = currentTrace.frames.findIndex((f) => canonicalStepId(f.stepId) === id);
  if (idx >= 0) setFrameIndex(idx);
};
