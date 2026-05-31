/**
 * Horizontal "neighborhood" strip: previous, current, next step thumbnails.
 * Each thumbnail shows the step's name, type, and the resulting state after
 * it ran as a flat byte row.
 *
 * Post-Slice-5.1 (MatrixState retired) the thumbnail renders the state as a
 * flat byte row rather than a 4×4 grid: every shipped cipher is byte-native,
 * so a 4×4 grid would impose an AES-column-major reading on non-AES states
 * (Serpent, DES, SHA) that don't have that structure — and it would clash
 * with the flat byte rows the main inspector (`PortFlowView`) shows. A
 * flat row reads honestly for every cipher.
 *
 * The current step is centered and emphasized. The previous/next
 * thumbnails are clickable shortcuts to navigate one frame in either
 * direction. At trace boundaries (frame 0, last frame) the corresponding
 * neighbor is rendered as a placeholder.
 */

import { formatByte } from "@/core/format";
import { frameStateOutBytes } from "@/core/frame-state";
import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useByteFormat } from "../stores/format";
import { getTrace, setFrame, useFrameIndex, useTraceVersion } from "../stores/trace";

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

// ─── Single thumbnail ────────────────────────────────────────────────────

type ThumbnailProps = {
  frame: TraceFrame | null;
  position: "prev" | "current" | "next";
  /** When provided the thumbnail is clickable. */
  onClick?: () => void;
};

const Thumbnail = (props: ThumbnailProps) => {
  const fmt = useByteFormat();
  // The flat byte sequence of the step's after-state — the `"state"` output
  // port (port-first, Slice 5.3c) with the legacy `stateAfter` field as the
  // fallback until 5.3e retires it. `createMemo` because it's read twice in
  // the JSX below (the `<Show when>` guard + the `<For>`).
  const stateBytes = createMemo<readonly number[]>(() => {
    const f = props.frame;
    if (!f) return [];
    const bytes = frameStateOutBytes(f);
    return bytes ? Array.from(bytes) : [];
  });

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
            <Show
              when={stateBytes().length > 0}
              fallback={<div class="muted small">(no state)</div>}
            >
              <div class="step-thumb-bytes">
                <For each={stateBytes()}>
                  {(byte) => <div class="bytes-cell">{formatByte(byte, fmt())}</div>}
                </For>
              </div>
            </Show>
          </>
        )}
      </Show>
    </div>
  );
};
