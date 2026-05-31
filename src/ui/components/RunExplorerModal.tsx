/**
 * Run Explorer Modal — Phase 2c/2d.
 *
 * Full-window overlay that displays every snapshot in the run history side
 * by side at the same step (matched by stepId, not numeric index, so the
 * comparison stays meaningful even if steps were reordered between runs).
 * Each tile carries a "delta string" describing what's different about that
 * run relative to the immediately prior snapshot — that's Phase 2d.
 *
 * Each visible tile renders the run's after-state for the SAME stepId the
 * main view's scrubber is on. If a run lacks that stepId (deleted step),
 * the tile shows "(n/a in this run)" rather than disappearing — the user
 * still wants to know that snapshot exists and that the step is missing
 * from it.
 *
 * Cells in each tile that differ from the immediately previous *visible*
 * run get the accent ring — chained, so the user can follow "what changed
 * step-by-step across this comparison set." Hiding a run shifts the
 * baseline to the next-visible run.
 *
 * The modal listens to the same global byte-format store as the rest of
 * the app, so toggling format updates the explorer in place.
 */

import { type ByteFormat, formatByte, formatBytes } from "@/core/format";
import { frameStateOutBytes } from "@/core/frame-state";
import { For, Show, createEffect, createMemo } from "solid-js";
import { useByteFormat } from "../stores/format";
import {
  type RunSnapshot,
  clearHistory,
  toggleSnapshotHidden,
  useHistory,
} from "../stores/history";
import { getTrace, useFrameIndex, useTraceVersion } from "../stores/trace";
import { describeDelta } from "./run-delta-format";

type Props = {
  isOpen: () => boolean;
  onClose: () => void;
};

export const RunExplorerModal = (props: Props) => {
  const history = useHistory();
  const fmt = useByteFormat();
  const frameIndex = useFrameIndex();
  const version = useTraceVersion();

  // The stepId the main view is currently on. We use this to find the
  // equivalent frame in every snapshot — Phase 1's stepId-first principle
  // applied to the run explorer.
  const currentStepId = createMemo<string | null>(() => {
    void version();
    return getTrace()?.frames[frameIndex()]?.stepId ?? null;
  });

  // Resolve each snapshot to the matrix state we'll render in its tile.
  // The tiles render in history order (oldest first → newest last); each
  // tile compares against the immediately previous *visible* tile, so we
  // pass a "diff baseline" through the For loop.
  type TileData = {
    snapshot: RunSnapshot;
    // The step's after-state bytes, rendered as a flat byte row. Post-Slice-5.1
    // (MatrixState retired) every cipher is byte-native, so the tile shows a
    // flat row for any width rather than a 4×4 grid (which would impose an
    // AES-column-major reading on non-AES states). null when the step isn't
    // in this run.
    stateAtStep: Uint8Array | null;
    isCurrent: boolean;
  };

  const tiles = createMemo<TileData[]>(() => {
    const stepId = currentStepId();
    const snaps = history();
    const lastIdx = snaps.length - 1;
    return snaps.map((snapshot, i) => {
      const frame = stepId ? snapshot.trace.frames.find((f) => f.stepId === stepId) : undefined;
      // Port-first read (Slice 5.3c): the `"state"` output port, falling back
      // to the legacy `stateAfter` field until 5.3e retires it.
      const stateAtStep = frame ? frameStateOutBytes(frame) : null;
      return { snapshot, stateAtStep, isCurrent: i === lastIdx };
    });
  });

  // Use the native <dialog> element: built-in escape-to-close, focus trap,
  // and ::backdrop styling. We drive showModal/close from the isOpen
  // signal via an effect so the host App just flips the flag.
  let dialogRef: HTMLDialogElement | undefined;
  createEffect(() => {
    const open = props.isOpen();
    const el = dialogRef;
    if (!el) return;
    if (open && !el.open) el.showModal();
    if (!open && el.open) el.close();
  });

  return (
    <dialog
      ref={dialogRef}
      class="modal"
      aria-label="Run Explorer"
      onClose={() => props.onClose()}
      // Backdrop click closes the modal. Keyboard-only users get Escape
      // routed through the native <dialog>'s cancel event → onClose above,
      // and onKeyDown here is a no-op stub solely to satisfy biome's a11y
      // pairing rule (click+key) — every meaningful key gesture is already
      // handled by the browser at the dialog level.
      onKeyDown={() => {}}
      onClick={(e) => {
        // Click on the dialog element itself (not a child) hits the
        // backdrop. The backdrop is a pseudo-element so it bubbles up
        // through the dialog element. Compare currentTarget to target.
        if (e.target === e.currentTarget) props.onClose();
      }}
    >
      {/* Inner wrapper holds the actual content; the dialog element only
          provides the modal chrome (backdrop + escape handling). */}
      <div class="modal-inner">
        <div class="modal-header">
          <h2>Run Explorer</h2>
          <span class="muted small">
            comparing on step: <code>{currentStepId() ?? "(no trace)"}</code>
          </span>
          <button
            type="button"
            class="modal-close"
            onClick={() => props.onClose()}
            aria-label="Close"
          >
            ×
          </button>
        </div>

        <div class="modal-body">
          <Show
            when={history().length > 0}
            fallback={
              <div class="muted">
                No runs in history yet — click <strong>run</strong> to create one.
              </div>
            }
          >
            <div class="run-tiles">
              <For each={tiles()}>
                {(tile, i) => {
                  // Baseline = the previous visible tile's state (used
                  // to highlight cells that newly changed in THIS tile).
                  // Walking backwards through tiles() so hidden tiles
                  // pass through without re-anchoring the baseline.
                  const previousVisibleState = (): Uint8Array | null => {
                    const all = tiles();
                    for (let j = i() - 1; j >= 0; j--) {
                      const t = all[j];
                      if (!t || t.snapshot.hidden) continue;
                      return t.stateAtStep;
                    }
                    return null;
                  };
                  return (
                    <RunTile
                      snapshot={tile.snapshot}
                      stateAtStep={tile.stateAtStep}
                      isCurrent={tile.isCurrent}
                      previousVisibleState={previousVisibleState()}
                      format={fmt()}
                    />
                  );
                }}
              </For>
            </div>
          </Show>
        </div>

        <div class="modal-footer">
          <button
            type="button"
            onClick={() => clearHistory()}
            disabled={history().length === 0}
            title="Drop all snapshots from the history"
          >
            clear history
          </button>
        </div>
      </div>
    </dialog>
  );
};

// ─── Per-run tile ─────────────────────────────────────────────────────────

const RunTile = (props: {
  snapshot: RunSnapshot;
  stateAtStep: Uint8Array | null;
  isCurrent: boolean;
  previousVisibleState: Uint8Array | null;
  format: ByteFormat;
}) => {
  const inputSummary = (): string => formatBytes(props.snapshot.inputBytes, props.format);
  const keySummary = (): string => formatBytes(props.snapshot.keyBytes, props.format);

  return (
    <div
      class="run-tile"
      classList={{
        "run-tile-current": props.isCurrent,
        "run-tile-hidden": props.snapshot.hidden,
      }}
    >
      <div class="run-tile-header">
        <span class="run-tile-id">
          Run #{props.snapshot.id}
          <Show when={props.isCurrent}>
            <span class="run-tile-tag"> (current)</span>
          </Show>
        </span>
        <button
          type="button"
          class="run-tile-hide-btn"
          onClick={() => toggleSnapshotHidden(props.snapshot.id)}
          title={props.snapshot.hidden ? "Show this run" : "Hide this run"}
        >
          {props.snapshot.hidden ? "show" : "hide"}
        </button>
      </div>

      <div class="run-tile-inputs small muted">
        <div>
          pt: <code>{truncateMiddle(inputSummary(), 28)}</code>
        </div>
        <div>
          key: <code>{truncateMiddle(keySummary(), 28)}</code>
        </div>
        <div class="run-tile-mode">mode: {props.snapshot.mode}</div>
      </div>

      <Show
        when={!props.snapshot.hidden}
        fallback={<div class="run-tile-matrix-empty muted small">(hidden)</div>}
      >
        <Show
          when={props.stateAtStep}
          fallback={<div class="run-tile-matrix-empty muted small">(stepId not in this run)</div>}
        >
          {(bytes) => (
            <div class="run-tile-bytes">
              <For each={Array.from(bytes())}>
                {(byte, i) => (
                  <div
                    class="bytes-cell"
                    classList={{
                      // Highlight cells that differ from the previous visible
                      // run's state at this step (the run-to-run diff overlay).
                      "diff-vs-prev":
                        props.previousVisibleState != null &&
                        props.previousVisibleState[i()] !== byte,
                    }}
                  >
                    {formatByte(byte, props.format)}
                  </div>
                )}
              </For>
            </div>
          )}
        </Show>
      </Show>

      <div class="run-tile-delta">
        <For each={describeDelta(props.snapshot.delta, props.format)}>
          {(line) => <div class="run-tile-delta-line small">{line}</div>}
        </For>
      </div>
    </div>
  );
};

/**
 * Squeeze a long byte-format string by elliding the middle. Used for the
 * tile header summary so input/key values stay one line. We elide rather
 * than wrap because the user cares about the FIRST and LAST bytes most
 * (they're where edits typically land).
 */
const truncateMiddle = (s: string, max: number): string => {
  if (s.length <= max) return s;
  const keep = Math.max(2, Math.floor((max - 1) / 2));
  return `${s.slice(0, keep)}…${s.slice(-keep)}`;
};
