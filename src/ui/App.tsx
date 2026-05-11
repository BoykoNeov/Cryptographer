/**
 * App shell. Owns the input form, the run trigger, the debounced auto-rerun
 * on spec edits, and the layout for everything below: timeline, neighborhood
 * strip, matrix view, step description, and the editable param editor.
 *
 * The interesting wiring is the createEffect at the bottom: when the user
 * edits the spec via ParamEditor, the spec signal changes; the effect
 * notices, debounces 200ms (so 256-cell S-box edits don't hammer the
 * runtime), and re-runs the trace. That's the "swap a value, watch the
 * trace update" loop the modularity demo lives on.
 *
 * Phase 3 added a hex/decimal/ASCII byte format toggle. The plaintext and
 * key fields hold their text in whichever format is currently active; the
 * Run handler parses with that format, and the output renders the bytes
 * back through it. Switching format mid-session re-renders the current
 * input text in place (parse with old format → re-format with new) so
 * the user doesn't lose their typed value.
 */

import { type ByteFormat, formatBytes, parseBytes, parseBytesWithLength } from "@/core/format";
import { runSpec } from "@/core/runtime";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, MatrixState } from "@/core/types";
import { Show, createEffect, createMemo, createSignal, on, onCleanup } from "solid-js";
import { MatrixView } from "./components/MatrixView";
import { ParamEditor } from "./components/ParamEditor";
import { StepDescription } from "./components/StepDescription";
import { StepList } from "./components/StepList";
import { StepStrip } from "./components/StepStrip";
import { TraceTimeline } from "./components/TraceTimeline";
import { setByteFormat, useByteFormat } from "./stores/format";
import {
  findPreviousRunFrameByStepId,
  pushSnapshot,
  setShowPreviousRun,
  useHistory,
  useShowPreviousRun,
} from "./stores/history";
import { installKeyboardShortcuts } from "./stores/keyboard";
import { registry } from "./stores/registry";
import { resetSpec, setMode, useMode, useSpec } from "./stores/spec";
import { getTrace, setTrace, useFrameIndex, useTraceVersion } from "./stores/trace";
import "./app.css";

// Default test vector from FIPS-197 Appendix C.1 — gives users a known
// good answer to compare against on first load. Stored as hex bytes;
// rendered through formatBytes at init so the on-screen value matches the
// user's current format choice (e.g. after a reload in decimal mode).
const DEFAULT_PT_BYTES = new Uint8Array([
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
]);
const DEFAULT_KEY_BYTES = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);

// How long after the last spec edit before we re-run the cipher. 200ms is
// long enough that fast typing on 256 S-box cells doesn't cause a re-run
// on every keystroke, but short enough to feel immediate.
const AUTO_RERUN_DEBOUNCE_MS = 200;

export const App = () => {
  const spec = useSpec();
  const mode = useMode();
  const fmt = useByteFormat();

  // Inputs — kept as strings (in whatever the current byte format is) so
  // the user can paste partial input without the field fighting them
  // mid-type. We validate on run.
  const [inputText, setInputText] = createSignal(formatBytes(DEFAULT_PT_BYTES, fmt()));
  const [keyText, setKeyText] = createSignal(formatBytes(DEFAULT_KEY_BYTES, fmt()));
  const [error, setError] = createSignal<string | null>(null);

  // Has the user successfully run the cipher at least once? If yes, spec
  // edits trigger an auto-rerun. If no, edits do nothing — we'd just be
  // throwing parse errors at the user before they've even hit "run."
  const [hasRunOnce, setHasRunOnce] = createSignal(false);

  // Wire window-level keyboard shortcuts (←/→ scrub, Home/End, PageUp/Down).
  // Tied to App's lifecycle via onCleanup inside the helper.
  installKeyboardShortcuts();

  /**
   * Run the current spec with the current inputs, push the resulting trace
   * into the trace store, and update error state. Doesn't throw — errors
   * are surfaced via setError so the UI can render them inline.
   */
  const run = (): void => {
    try {
      setError(null);
      let inputBytes: Uint8Array;
      try {
        inputBytes = parseBytesWithLength(inputText(), fmt(), 16);
      } catch (e) {
        throw new Error(`${inputLabel()}: ${e instanceof Error ? e.message : String(e)}`);
      }
      let keyBytes: Uint8Array;
      try {
        keyBytes = parseBytesWithLength(keyText(), fmt(), 16);
      } catch (e) {
        throw new Error(`key: ${e instanceof Error ? e.message : String(e)}`);
      }
      const initialAux = new Map<string, AuxValue>([["key", keyBytes]]);
      const currentSpec = spec();
      const trace = runSpec(currentSpec, registry, {
        initialState: matrixFromBytes(inputBytes),
        initialAux,
      });
      setTrace(trace);
      // Push BEFORE setHasRunOnce so the snapshot captures the configuration
      // that produced this trace. The snapshot store dedups identical re-runs
      // automatically, so the auto-rerun-on-spec-edit path won't spam history.
      pushSnapshot({
        inputBytes,
        keyBytes,
        mode: mode(),
        spec: currentSpec,
        trace,
      });
      setHasRunOnce(true);
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  // Auto re-run on spec edit, debounced. The `on(spec, ...)` form runs ONLY
  // when the spec signal changes, not on initial setup — important because
  // we don't want to auto-run before the user has hit the button once.
  createEffect(
    on(
      spec,
      () => {
        if (!hasRunOnce()) return;
        const handle = window.setTimeout(run, AUTO_RERUN_DEBOUNCE_MS);
        onCleanup(() => window.clearTimeout(handle));
      },
      { defer: true },
    ),
  );

  /**
   * Switch byte format. Re-renders the current input/key text in the new
   * format so the user doesn't lose their value. If a field doesn't parse
   * cleanly in the old format (mid-edit garbage), leave the raw text alone
   * — the user will see an error on the next Run anyway, no point clobbering
   * their in-flight typing.
   */
  const changeFormat = (next: ByteFormat): void => {
    const prev = fmt();
    if (prev === next) return;
    setInputText(reformatTextOrKeep(inputText(), prev, next));
    setKeyText(reformatTextOrKeep(keyText(), prev, next));
    setByteFormat(next);
  };

  // Reactive derived values for the trace view.
  const frameIndex = useFrameIndex();
  const version = useTraceVersion();

  const currentFrame = createMemo(() => {
    void version();
    return getTrace()?.frames[frameIndex()] ?? null;
  });

  const outputText = createMemo(() => {
    void version();
    const t = getTrace();
    if (!t || t.finalState.shape !== "matrix4x4-bytes") return null;
    return formatBytes(t.finalState.bytes, fmt());
  });

  // Phase 2b — overlay: look up the same-stepId frame from the run just
  // before the current one. We memoize on (history, currentFrame.stepId)
  // so a scrub through the trace re-uses the same snapshot's frames
  // without re-walking them on every render.
  const history = useHistory();
  const showPrev = useShowPreviousRun();
  const previousRunFrame = createMemo(() => {
    if (!showPrev()) return null;
    const f = currentFrame();
    if (!f) return null;
    return findPreviousRunFrameByStepId(history(), f.stepId);
  });
  // Snapshot count drives the "compare runs" button label and disables the
  // overlay toggle when there's nothing to compare against (1 run only).
  const historyCount = createMemo(() => history().length);
  const canCompare = createMemo(() => historyCount() >= 2);

  // Labels switch between encrypt/decrypt modes so the UI doesn't lie.
  const inputLabel = () => (mode() === "encrypt" ? "plaintext" : "ciphertext");
  const outputLabel = () => (mode() === "encrypt" ? "ciphertext" : "plaintext");

  return (
    <div class="app">
      <header>
        <h1>Cryptographer</h1>
        <span class="cipher-name">{spec().name}</span>
        <span class="muted small kbd-hint">←/→ step · Home/End jump · PgUp/PgDn round</span>
      </header>

      {/* ─── Inputs row ─────────────────────────────────────────────── */}
      <section class="inputs">
        <label>
          mode
          <select
            value={mode()}
            onChange={(e) => setMode(e.currentTarget.value as "encrypt" | "decrypt")}
          >
            <option value="encrypt">encrypt</option>
            <option value="decrypt">decrypt</option>
          </select>
        </label>
        {/* Group of buttons (not a single form control) → semantic
            <fieldset>/<legend> per biome's a11y lint. The group browses
            as one labeled chunk for screen readers. */}
        <fieldset class="input-group">
          <legend class="input-group-label">bytes</legend>
          <div class="format-toggle">
            <button
              type="button"
              classList={{ active: fmt() === "hex" }}
              onClick={() => changeFormat("hex")}
            >
              hex
            </button>
            <button
              type="button"
              classList={{ active: fmt() === "decimal" }}
              onClick={() => changeFormat("decimal")}
            >
              dec
            </button>
            <button
              type="button"
              classList={{ active: fmt() === "ascii" }}
              onClick={() => changeFormat("ascii")}
            >
              ASCII
            </button>
          </div>
        </fieldset>
        <label>
          {inputLabel()} ({fmt()})
          <input
            value={inputText()}
            onInput={(e) => setInputText(e.currentTarget.value)}
            spellcheck={false}
          />
        </label>
        <label>
          key ({fmt()})
          <input
            value={keyText()}
            onInput={(e) => setKeyText(e.currentTarget.value)}
            spellcheck={false}
          />
        </label>
        <button type="button" onClick={run}>
          run
        </button>
        <button type="button" onClick={resetSpec} title="Restore the canonical spec for this mode">
          reset spec
        </button>
      </section>

      {/* ─── Errors and result hex ───────────────────────────────────── */}
      <Show when={error()}>
        <div class="error">{error()}</div>
      </Show>

      <Show when={!error() && outputText()}>
        <div class="result">
          {outputLabel()} ({fmt()}): <code>{outputText()}</code>
        </div>
      </Show>

      {/* ─── Trace timeline scrubber ─────────────────────────────────── */}
      <TraceTimeline />

      {/* ─── Main trace view: strip, matrix, description, editor ─────── */}
      <section class="trace-view">
        <Show
          when={currentFrame()}
          fallback={<div class="muted">run the cipher to see step-by-step state</div>}
        >
          {(frame) => (
            <>
              {/* Frame header: full path/id (the strip below shows
                  shortened labels; this is the unambiguous reference). */}
              <div class="frame-header">
                <span class="frame-step">
                  {frame().path.length > 0 ? `${frame().path.join(" › ")} › ` : ""}
                  {frame().stepId}
                </span>
                <div class="frame-header-right">
                  {/* Phase 2b — overlay toggle. Disabled until we have a
                      second snapshot to compare against, so the user can't
                      ask for an overlay that doesn't exist yet. */}
                  <label
                    class="compare-toggle"
                    title="Show previous run alongside the current matrix"
                  >
                    <input
                      type="checkbox"
                      checked={showPrev()}
                      disabled={!canCompare()}
                      onChange={(e) => setShowPreviousRun(e.currentTarget.checked)}
                    />
                    compare to previous run
                    <Show when={canCompare()}>
                      <span class="compare-count">({historyCount()} runs)</span>
                    </Show>
                  </label>
                  <span class="frame-type">{frame().stepType}</span>
                </div>
              </div>

              {/* Neighborhood strip: prev / current / next thumbnails. */}
              <StepStrip />

              {/* Matrix view of the current step's before/after state. */}
              <Show
                when={
                  frame().stateBefore.shape === "matrix4x4-bytes" &&
                  frame().stateAfter.shape === "matrix4x4-bytes"
                }
                fallback={<div class="muted">non-matrix state — view not yet implemented</div>}
              >
                <MatrixView
                  before={frame().stateBefore as MatrixState}
                  after={frame().stateAfter as MatrixState}
                  previousAfter={
                    previousRunFrame()?.stateAfter.shape === "matrix4x4-bytes"
                      ? (previousRunFrame()?.stateAfter as MatrixState)
                      : null
                  }
                />
              </Show>

              {/* Human-readable explanation of what this step does. */}
              <StepDescription frame={frame()} />

              {/* Editable params for the current step. */}
              <ParamEditor frame={frame()} />
            </>
          )}
        </Show>
      </section>

      {/* ─── Sidebar: collapsible step tree ─────────────────────────── */}
      <aside class="step-list-pane">
        <h2>steps</h2>
        <StepList />
      </aside>
    </div>
  );
};

/**
 * Best-effort re-render of an input field's text when the format toggles.
 * If the field parses cleanly in the old format, re-emit it in the new
 * one. If not (user typed partial / invalid data), leave the raw text
 * alone — better than clobbering their in-progress edit.
 */
const reformatTextOrKeep = (text: string, from: ByteFormat, to: ByteFormat): string => {
  try {
    const bytes = parseBytes(text, from);
    return formatBytes(bytes, to);
  } catch {
    return text;
  }
};
