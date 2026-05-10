import { createSignal } from "solid-js";
import type { Trace } from "@/core/types";

/**
 * The trace itself lives outside the reactive system — only the index is
 * reactive. A 50,000-frame trace inside a Solid store would tank perf.
 */
let currentTrace: Trace | null = null;

const [frameIndex, setFrameIndex] = createSignal(0);
const [version, setVersion] = createSignal(0);

export const setTrace = (trace: Trace) => {
  currentTrace = trace;
  setFrameIndex(0);
  setVersion((v) => v + 1);
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
