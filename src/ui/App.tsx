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
 */

import { runSpec } from "@/core/runtime";
import { bytesFromHex, hexFromBytes } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, MatrixState } from "@/core/types";
import { Show, createEffect, createMemo, createSignal, on, onCleanup } from "solid-js";
import { MatrixView } from "./components/MatrixView";
import { ParamEditor } from "./components/ParamEditor";
import { StepDescription } from "./components/StepDescription";
import { StepList } from "./components/StepList";
import { StepStrip } from "./components/StepStrip";
import { TraceTimeline } from "./components/TraceTimeline";
import { installKeyboardShortcuts } from "./stores/keyboard";
import { registry } from "./stores/registry";
import { resetSpec, setMode, useMode, useSpec } from "./stores/spec";
import { getTrace, setTrace, useFrameIndex, useTraceVersion } from "./stores/trace";
import "./app.css";

// Default test vector from FIPS-197 Appendix C.1 — gives users a known
// good answer to compare against on first load.
const DEFAULT_PT = "00112233445566778899aabbccddeeff";
const DEFAULT_KEY = "000102030405060708090a0b0c0d0e0f";

// How long after the last spec edit before we re-run the cipher. 200ms is
// long enough that fast typing on 256 S-box cells doesn't cause a re-run
// on every keystroke, but short enough to feel immediate.
const AUTO_RERUN_DEBOUNCE_MS = 200;

export const App = () => {
  const spec = useSpec();
  const mode = useMode();

  // Inputs — kept as strings so the user can paste partial hex without
  // the input fighting them mid-type. We validate on run.
  const [inputHex, setInputHex] = createSignal(DEFAULT_PT);
  const [keyHex, setKeyHex] = createSignal(DEFAULT_KEY);
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
      const inputBytes = bytesFromHex(inputHex());
      if (inputBytes.length !== 16) {
        throw new Error(
          `${inputLabel()} must be 16 bytes (32 hex chars), got ${inputBytes.length}`,
        );
      }
      const keyBytes = bytesFromHex(keyHex());
      if (keyBytes.length !== 16) {
        throw new Error(`key must be 16 bytes (32 hex chars), got ${keyBytes.length}`);
      }
      const initialAux = new Map<string, AuxValue>([["key", keyBytes]]);
      const trace = runSpec(spec(), registry, {
        initialState: matrixFromBytes(inputBytes),
        initialAux,
      });
      setTrace(trace);
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

  // Reactive derived values for the trace view.
  const frameIndex = useFrameIndex();
  const version = useTraceVersion();

  const currentFrame = createMemo(() => {
    void version();
    return getTrace()?.frames[frameIndex()] ?? null;
  });

  const outputHex = createMemo(() => {
    void version();
    const t = getTrace();
    if (!t || t.finalState.shape !== "matrix4x4-bytes") return null;
    return hexFromBytes(t.finalState.bytes);
  });

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
        <label>
          {inputLabel()} (hex)
          <input
            value={inputHex()}
            onInput={(e) => setInputHex(e.currentTarget.value)}
            spellcheck={false}
          />
        </label>
        <label>
          key (hex)
          <input
            value={keyHex()}
            onInput={(e) => setKeyHex(e.currentTarget.value)}
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

      <Show when={!error() && outputHex()}>
        <div class="result">
          {outputLabel()}: <code>{outputHex()}</code>
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
                <span class="frame-type">{frame().stepType}</span>
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
