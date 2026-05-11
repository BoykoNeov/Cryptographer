/**
 * Horizontal "neighborhood" strip: previous, current, next step thumbnails.
 * Each thumbnail shows the step's name, type, and the resulting state
 * after it ran (a small 4×4 byte grid).
 *
 * The current step is centered and emphasized. The previous/next
 * thumbnails are clickable shortcuts to navigate one frame in either
 * direction. At trace boundaries (frame 0, last frame) the corresponding
 * neighbor is rendered as a placeholder.
 */

import type { MatrixState, TraceFrame } from "@/core/types";
import { Show, createMemo } from "solid-js";
import { findPreviousRunFrameByStepId, useHistory, useShowPreviousRun } from "../stores/history";
import { getTrace, setFrame, useFrameIndex, useTraceVersion } from "../stores/trace";
import { TinyMatrix } from "./TinyMatrix";

export const StepStrip = () => {
  const frameIndex = useFrameIndex();
  const version = useTraceVersion();

  // Memoize the {prev, current, next} triple. Without createMemo, each
  // <Thumbnail frame={…().prev|.current|.next}> binding would recompute the
  // object independently — three trace lookups per render where one suffices.
  const neighborhood = createMemo<{
    prev: TraceFrame | null;
    current: TraceFrame | null;
    next: TraceFrame | null;
  }>(() => {
    // Track the version signal so the memo invalidates when the trace
    // is replaced (e.g. after a spec edit triggers a rerun).
    void version();
    const t = getTrace();
    if (!t) return { prev: null, current: null, next: null };
    const i = frameIndex();
    return {
      prev: t.frames[i - 1] ?? null,
      current: t.frames[i] ?? null,
      next: t.frames[i + 1] ?? null,
    };
  });

  return (
    <div class="step-strip">
      <Thumbnail
        frame={neighborhood().prev}
        position="prev"
        onClick={() => setFrame(frameIndex() - 1)}
      />
      <Thumbnail frame={neighborhood().current} position="current" />
      <Thumbnail
        frame={neighborhood().next}
        position="next"
        onClick={() => setFrame(frameIndex() + 1)}
      />
    </div>
  );
};

/**
 * Resolve the previous-run after-state for a given frame, honoring the
 * "compare to previous run" toggle. Pulls from the history store; returns
 * null when the toggle is off or there's no prior run. Shared by every
 * thumbnail in the strip so the per-step comparison is consistent.
 */
const usePreviousMatrixFor = (frame: () => TraceFrame | null) => {
  const history = useHistory();
  const showPrev = useShowPreviousRun();
  return createMemo<MatrixState | null>(() => {
    if (!showPrev()) return null;
    const f = frame();
    if (!f) return null;
    const prev = findPreviousRunFrameByStepId(history(), f.stepId);
    if (!prev || prev.stateAfter.shape !== "matrix4x4-bytes") return null;
    return prev.stateAfter as MatrixState;
  });
};

// ─── Single thumbnail ────────────────────────────────────────────────────

type ThumbnailProps = {
  frame: TraceFrame | null;
  position: "prev" | "current" | "next";
  /** When provided the thumbnail is clickable. */
  onClick?: () => void;
};

const Thumbnail = (props: ThumbnailProps) => {
  // Only render the matrix view when we actually have a matrix state.
  // Other state shapes (bytes, bitvec, bigint) will get their own tiny
  // views in the future; for now they fall through to a placeholder.
  const matrixState = (): MatrixState | null => {
    const f = props.frame;
    if (!f || f.stateAfter.shape !== "matrix4x4-bytes") return null;
    return f.stateAfter as MatrixState;
  };

  // Phase 2b — per-thumbnail previous-run comparison. Reads the same toggle
  // the main MatrixView uses so the strip stays in sync.
  const previousMatrix = usePreviousMatrixFor(() => props.frame);

  // The visible label for the step. We trim path noise — usually the
  // last segment of the path plus the step name conveys plenty.
  const label = (): string => {
    const f = props.frame;
    if (!f) return "";
    const lastGroup = f.path[f.path.length - 1];
    const stepShort = f.stepId.split(".").pop() ?? f.stepId;
    return lastGroup ? `${lastGroup} › ${stepShort}` : stepShort;
  };

  return (
    <div
      class="step-thumb"
      classList={{
        "step-thumb-current": props.position === "current",
        "step-thumb-edge": props.frame === null,
        "step-thumb-clickable": !!props.onClick && props.frame !== null,
      }}
      onClick={() => props.onClick?.()}
      role={props.onClick ? "button" : undefined}
      tabindex={props.onClick && props.frame ? 0 : undefined}
      onKeyDown={(e) => {
        // Keyboard accessibility for the clickable thumbnails.
        if ((e.key === "Enter" || e.key === " ") && props.onClick) {
          e.preventDefault();
          props.onClick();
        }
      }}
    >
      <div class="step-thumb-position">
        {props.position === "prev"
          ? "◀ previous"
          : props.position === "next"
            ? "next ▶"
            : "current"}
      </div>

      <Show
        when={props.frame}
        fallback={
          <div class="step-thumb-empty muted">
            {props.position === "prev" ? "(start of trace)" : "(end of trace)"}
          </div>
        }
      >
        {(frame) => (
          <>
            <div class="step-thumb-label">{label()}</div>
            <div class="step-thumb-type">{frame().stepType}</div>
            <Show when={matrixState()} fallback={<div class="muted small">(non-matrix state)</div>}>
              {(state) => <TinyMatrix state={state()} previousState={previousMatrix()} />}
            </Show>
          </>
        )}
      </Show>
    </div>
  );
};
