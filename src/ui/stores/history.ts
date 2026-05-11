/**
 * Run-history store. Holds up to MAX_HISTORY recent run snapshots in a ring
 * buffer. Each snapshot captures everything we need to "go back and look":
 * the inputs, the spec, the trace, and a precomputed delta against the
 * immediately prior snapshot.
 *
 * Why we store the precomputed delta instead of computing on render: the
 * RunExplorer renders many snapshot tiles at once and we want stable, cheap
 * lookups. The delta is small (handful of byte diffs + param-key list) and
 * never changes once a snapshot is in the buffer.
 *
 * Snapshots are pushed once per successful `run()` in App.tsx — that covers
 * both manual Run-button presses and the debounced auto-rerun after spec
 * edits. Identical runs (no input/key/spec change) are deduplicated so the
 * buffer doesn't fill up with no-op re-runs of the same configuration; the
 * earliest snapshot in the dedup chain stays anchored, so the user can
 * compare back to their starting point even after a long editing session.
 *
 * Eviction is FIFO at MAX_HISTORY + 1 inserts. Hidden snapshots count
 * toward capacity — hiding is a view filter, not a storage strategy.
 */

import { type SpecParamDiff, compareSpecs } from "@/core/spec-mutations";
import type { CipherSpec, Trace, TraceFrame } from "@/core/types";
import { createSignal } from "solid-js";
import type { Mode } from "./spec";

/** Largest number of snapshots retained. Plan calls for 5; tune here if needed. */
export const MAX_HISTORY = 5;

/** A single byte position that changed between two consecutive runs. */
export type ByteDiff = {
  readonly index: number;
  readonly from: number;
  readonly to: number;
};

/** Everything different about a run relative to the immediately prior snapshot. */
export type RunDelta = {
  readonly inputChanged: readonly ByteDiff[];
  readonly keyChanged: readonly ByteDiff[];
  readonly paramsChanged: readonly SpecParamDiff[];
};

export type RunSnapshot = {
  /** Monotonic id; first snapshot is 1. Never reused after eviction. */
  readonly id: number;
  readonly capturedAt: number;
  readonly inputBytes: Uint8Array;
  readonly keyBytes: Uint8Array;
  readonly mode: Mode;
  /** Snapshot of the spec reference at run time. Specs are immutable trees. */
  readonly spec: CipherSpec;
  readonly trace: Trace;
  /** Delta vs the immediately previous snapshot in the buffer, or null for the first. */
  readonly delta: RunDelta | null;
  /** User-toggled view flag: when hidden, the explorer doesn't render this snapshot. */
  readonly hidden: boolean;
};

// ─── Store ────────────────────────────────────────────────────────────────

let nextId = 1;
const [history, setHistory] = createSignal<readonly RunSnapshot[]>([]);

export const useHistory = () => history;

/**
 * Push a new run snapshot. Computes the delta vs the most recent snapshot
 * automatically. If the new run is byte-for-byte identical to the most
 * recent snapshot (same input, key, mode, spec), the push is a no-op so
 * the buffer doesn't accumulate exact duplicates.
 *
 * `inputBytes` and `keyBytes` are copied into the snapshot — the caller's
 * Uint8Array is free to be mutated afterwards without corrupting history.
 */
export const pushSnapshot = (params: {
  inputBytes: Uint8Array;
  keyBytes: Uint8Array;
  mode: Mode;
  spec: CipherSpec;
  trace: Trace;
}): void => {
  const prev = history()[history().length - 1] ?? null;
  // Copy the byte arrays so we own them — the caller might pass typed-array
  // views into longer buffers, or mutate after the call.
  const inputBytes = new Uint8Array(params.inputBytes);
  const keyBytes = new Uint8Array(params.keyBytes);

  // Deduplication: if every observable input is identical to the latest
  // snapshot, this run produces an identical trace and we'd just be churning
  // the buffer. Skip.
  if (prev && isIdenticalToPrev(prev, inputBytes, keyBytes, params.mode, params.spec)) {
    return;
  }

  const delta = prev ? computeDelta(prev, inputBytes, keyBytes, params.spec) : null;

  const snapshot: RunSnapshot = {
    id: nextId++,
    capturedAt: Date.now(),
    inputBytes,
    keyBytes,
    mode: params.mode,
    spec: params.spec,
    trace: params.trace,
    delta,
    hidden: false,
  };

  // Append, then evict oldest if we overflowed.
  const next = [...history(), snapshot];
  if (next.length > MAX_HISTORY) next.shift();
  setHistory(next);
};

/** Toggle the per-snapshot `hidden` flag. View-only — snapshot stays in the buffer. */
export const toggleSnapshotHidden = (id: number): void => {
  setHistory((h) => h.map((s) => (s.id === id ? { ...s, hidden: !s.hidden } : s)));
};

/** Drop every snapshot. Resets the monotonic id so the next snapshot is #1 again. */
export const clearHistory = (): void => {
  setHistory([]);
  nextId = 1;
};

// ─── Previous-run overlay toggle (Phase 2b) ───────────────────────────────
// Whether the matrix views render an extra "previous run" grid alongside
// the current step's state. The toggle is global — every matrix display
// site reads the same signal — so flipping it propagates everywhere.

const [showPreviousRun, setShowPreviousRunSignal] = createSignal(true);

export const useShowPreviousRun = () => showPreviousRun;
export const setShowPreviousRun = (v: boolean): void => {
  setShowPreviousRunSignal(v);
};

/**
 * Look up the frame from the second-most-recent snapshot that has the
 * given `stepId`. The current run is the most recent snapshot; comparing
 * against the one before it gives the "what changed last edit" view that
 * Phase 2b is built around. Returns null when history has fewer than two
 * snapshots or the stepId is missing from the prior trace (deleted step).
 *
 * stepId-based lookup (not numeric index) so insertions/removals between
 * runs don't pull the comparison off the byte the user is inspecting —
 * matches the Phase 1 frame-preservation principle.
 */
export const findPreviousRunFrameByStepId = (
  snapshots: readonly RunSnapshot[],
  stepId: string,
): TraceFrame | null => {
  if (snapshots.length < 2) return null;
  const prev = snapshots[snapshots.length - 2];
  if (!prev) return null;
  return prev.trace.frames.find((f) => f.stepId === stepId) ?? null;
};

// ─── Internals ────────────────────────────────────────────────────────────

const isIdenticalToPrev = (
  prev: RunSnapshot,
  inputBytes: Uint8Array,
  keyBytes: Uint8Array,
  mode: Mode,
  spec: CipherSpec,
): boolean => {
  if (prev.mode !== mode) return false;
  if (prev.spec !== spec && compareSpecs(prev.spec, spec).length > 0) return false;
  if (!bytesEqual(prev.inputBytes, inputBytes)) return false;
  if (!bytesEqual(prev.keyBytes, keyBytes)) return false;
  return true;
};

const computeDelta = (
  prev: RunSnapshot,
  inputBytes: Uint8Array,
  keyBytes: Uint8Array,
  spec: CipherSpec,
): RunDelta => ({
  inputChanged: diffBytes(prev.inputBytes, inputBytes),
  keyChanged: diffBytes(prev.keyBytes, keyBytes),
  paramsChanged: compareSpecs(prev.spec, spec),
});

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
};

const diffBytes = (a: Uint8Array, b: Uint8Array): readonly ByteDiff[] => {
  const out: ByteDiff[] = [];
  const len = Math.max(a.length, b.length);
  for (let i = 0; i < len; i++) {
    const av = a[i] ?? 0;
    const bv = b[i] ?? 0;
    if (av !== bv) out.push({ index: i, from: av, to: bv });
  }
  return out;
};

/** Test-only reset; production code uses `clearHistory`. */
export const __resetHistoryForTests = (): void => {
  clearHistory();
};
