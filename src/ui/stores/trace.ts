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

  currentTrace = trace;

  let nextIdx = 0;
  if (hadPriorTrace && trace.frames.length > 0) {
    if (previousStepId !== undefined) {
      const found = trace.frames.findIndex((f) => f.stepId === previousStepId);
      // Same stepId in the new trace → land on it.
      // Not found → clamp the old index into the new range as a safety net.
      nextIdx = found >= 0 ? found : Math.min(previousIdx, trace.frames.length - 1);
    } else {
      nextIdx = Math.min(previousIdx, trace.frames.length - 1);
    }
  }

  setFrameIndex(Math.max(0, nextIdx));
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
};

export const getTrace = (): Trace | null => currentTrace;

export const useFrameIndex = () => frameIndex;
export const setFrame = (n: number) => {
  if (!currentTrace) return;
  const max = currentTrace.frames.length - 1;
  setFrameIndex(Math.max(0, Math.min(n, max)));
};

/** Bumps when the trace is replaced. Read this in createMemo to invalidate views. */
export const useTraceVersion = () => version;
