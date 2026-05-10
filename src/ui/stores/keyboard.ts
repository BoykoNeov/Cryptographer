/**
 * Window-level keyboard shortcuts for timeline scrubbing. Attaches a
 * keydown listener that translates arrow keys into setFrame() calls.
 *
 * Ignored when focus is on an editable element (inputs, textareas,
 * selects, contentEditable) so typing into the plaintext / key / S-box
 * cells still works normally.
 *
 * Shortcuts:
 *   ←  / →            scrub one frame back / forward
 *   Home / End        first / last frame
 *   PageUp / PageDown previous / next group boundary (e.g. previous round)
 */

import type { TraceFrame } from "@/core/types";
import { onCleanup } from "solid-js";
import { getTrace, setFrame, useFrameIndex } from "./trace";

/** True if the key event originated inside an editable element. */
const isEditableTarget = (target: EventTarget | null): boolean => {
  if (!(target instanceof HTMLElement)) return false;
  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") return true;
  if (target.isContentEditable) return true;
  return false;
};

/**
 * Top-level group key for a frame. Frames with no group (e.g. the
 * key-expansion step at the top level of the spec) get a sentinel so
 * they group together — useful so PageDown skips past them as a unit.
 */
const groupKey = (f: TraceFrame): string => f.path[0] ?? "<root>";

/** Find the first frame with a different top-level group, in either direction. */
const findGroupBoundary = (
  frames: readonly TraceFrame[],
  fromIndex: number,
  direction: 1 | -1,
): number => {
  if (frames.length === 0) return 0;
  const fromFrame = frames[fromIndex];
  if (!fromFrame) return fromIndex;
  const fromGroup = groupKey(fromFrame);

  let i = fromIndex + direction;
  while (i >= 0 && i < frames.length) {
    const f = frames[i];
    if (f && groupKey(f) !== fromGroup) {
      // First frame of the new group is what we want.
      return i;
    }
    i += direction;
  }
  // No more groups in this direction — clamp to the trace edge.
  return direction > 0 ? frames.length - 1 : 0;
};

export const installKeyboardShortcuts = (): void => {
  const handler = (e: KeyboardEvent): void => {
    if (isEditableTarget(e.target)) return;

    const trace = getTrace();
    if (!trace || trace.frames.length === 0) return;

    const idx = useFrameIndex()();
    const last = trace.frames.length - 1;

    switch (e.key) {
      case "ArrowLeft":
        setFrame(idx - 1);
        e.preventDefault();
        return;
      case "ArrowRight":
        setFrame(idx + 1);
        e.preventDefault();
        return;
      case "Home":
        setFrame(0);
        e.preventDefault();
        return;
      case "End":
        setFrame(last);
        e.preventDefault();
        return;
      case "PageUp":
        setFrame(findGroupBoundary(trace.frames, idx, -1));
        e.preventDefault();
        return;
      case "PageDown":
        setFrame(findGroupBoundary(trace.frames, idx, 1));
        e.preventDefault();
        return;
    }
  };

  window.addEventListener("keydown", handler);
  // Solid auto-disposes onCleanup when called inside a reactive scope
  // (e.g. inside App's render function). Keeps the listener tied to the
  // App's lifecycle.
  onCleanup(() => window.removeEventListener("keydown", handler));
};
