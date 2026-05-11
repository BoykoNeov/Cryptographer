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
 *
 * Phase 4 (this commit) added PKCS#7 padding as a visible step. When the
 * selector is on PKCS#7, encrypt input can be 0..15 bytes; the spec gains
 * a `pkcs7-pad → load-block` prefix that's rendered in the trace, and the
 * inverse `store-block → pkcs7-unpad` suffix on decrypt produces a
 * variable-length plaintext from the 16-byte ciphertext. The Run handler
 * routes through scheme-aware parsing + initial-state shape selection.
 */

import {
  type ByteFormat,
  formatByte,
  formatBytes,
  parseBytes,
  parseBytesWithLength,
} from "@/core/format";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import { matrixFromBytes } from "@/core/state/matrix";
import type { AuxValue, BytesState, MatrixState, State, TraceFrame } from "@/core/types";
import { For, Show, createEffect, createMemo, createSignal, on, onCleanup } from "solid-js";
import { BytesView } from "./components/BytesView";
import { MatrixView } from "./components/MatrixView";
import { ParamEditor } from "./components/ParamEditor";
import { RunExplorerModal } from "./components/RunExplorerModal";
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
import {
  PADDING_SCHEME_LABELS,
  PADDING_SCHEME_OPTIONS,
  type PaddingScheme,
  paddingLimits,
  usePaddingScheme,
} from "./stores/padding";
import { registry } from "./stores/registry";
import { resetSpec, setMode, setPadding, useMode, useSpec } from "./stores/spec";
import { getTrace, setTrace, useFrameIndex, useTraceVersion } from "./stores/trace";
import "./app.css";

// Default test vector from FIPS-197 Appendix C.1 — gives users a known
// good answer to compare against on first load when padding="none". Stored
// as hex bytes; rendered through formatBytes at init so the on-screen value
// matches the user's current format choice (e.g. after a reload in decimal
// mode).
const DEFAULT_PT_BYTES = new Uint8Array([
  0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
]);
const DEFAULT_KEY_BYTES = new Uint8Array([
  0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
]);
// When the user reloads with padding="pkcs7" persisted, the FIPS vector
// (16 bytes) would immediately fail the 0..15 length cap. Default to a
// short, visible word so the trace produces a clean pad/unpad frame on
// first Run. The bytes are the ASCII codepoints for "apple".
const DEFAULT_PKCS7_PT_BYTES = new Uint8Array([0x61, 0x70, 0x70, 0x6c, 0x65]);

// How long after the last spec edit before we re-run the cipher. 200ms is
// long enough that fast typing on 256 S-box cells doesn't cause a re-run
// on every keystroke, but short enough to feel immediate.
const AUTO_RERUN_DEBOUNCE_MS = 200;

export const App = () => {
  const spec = useSpec();
  const mode = useMode();
  const fmt = useByteFormat();
  const padding = usePaddingScheme();

  // Inputs — kept as strings (in whatever the current byte format is) so
  // the user can paste partial input without the field fighting them
  // mid-type. We validate on run. Initial plaintext varies by initial
  // padding scheme: pkcs7+encrypt gets the short "apple" so the user sees
  // padding working immediately on a fresh reload.
  const initialPtBytes =
    padding() === "pkcs7" && mode() === "encrypt" ? DEFAULT_PKCS7_PT_BYTES : DEFAULT_PT_BYTES;
  const [inputText, setInputText] = createSignal(formatBytes(initialPtBytes, fmt()));
  const [keyText, setKeyText] = createSignal(formatBytes(DEFAULT_KEY_BYTES, fmt()));
  const [error, setError] = createSignal<string | null>(null);

  // Has the user successfully run the cipher at least once? If yes, spec
  // edits trigger an auto-rerun. If no, edits do nothing — we'd just be
  // throwing parse errors at the user before they've even hit "run."
  const [hasRunOnce, setHasRunOnce] = createSignal(false);

  // Phase 2c — Run Explorer modal open state. Local to the App component;
  // the modal pulls everything it needs from the global stores.
  const [explorerOpen, setExplorerOpen] = createSignal(false);

  // Wire window-level keyboard shortcuts (←/→ scrub, Home/End, PageUp/Down).
  // Tied to App's lifecycle via onCleanup inside the helper.
  installKeyboardShortcuts();

  /**
   * Run the current spec with the current inputs, push the resulting trace
   * into the trace store, and update error state. Doesn't throw — errors
   * are surfaced via setError so the UI can render them inline.
   *
   * Scheme-aware: the (mode, scheme) pair picks the initial state shape
   * and the allowed input-length range. Encrypt+pkcs7 seeds with BytesState
   * (variable length, 0..15); everything else seeds with the 16-byte matrix.
   */
  const run = (): void => {
    try {
      setError(null);

      // Parse the input as raw bytes first, no length enforcement — we'll
      // do scheme-specific validation below for a friendlier error.
      let inputBytes: Uint8Array;
      try {
        inputBytes = parseBytes(inputText(), fmt());
      } catch (e) {
        throw new Error(`${inputLabel()}: ${e instanceof Error ? e.message : String(e)}`);
      }
      const { min, max } = paddingLimits(mode(), padding());
      if (inputBytes.length < min || inputBytes.length > max) {
        throw new Error(formatLengthError(mode(), padding(), inputBytes.length, min, max));
      }

      // Key is always exactly 16 bytes for AES-128 regardless of padding.
      let keyBytes: Uint8Array;
      try {
        keyBytes = parseBytesWithLength(keyText(), fmt(), 16);
      } catch (e) {
        throw new Error(`key: ${e instanceof Error ? e.message : String(e)}`);
      }

      // Initial state shape: bytes for encrypt+pkcs7 (variable-length input
      // entering the pad chain); matrix for everything else (today's flow).
      const initialState: State =
        mode() === "encrypt" && padding() === "pkcs7"
          ? makeBytesState(inputBytes)
          : matrixFromBytes(inputBytes);

      const initialAux = new Map<string, AuxValue>([["key", keyBytes]]);
      const currentSpec = spec();
      const trace = runSpec(currentSpec, registry, {
        initialState,
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

  /**
   * Switch padding scheme. Persists the choice, rebuilds the spec with the
   * new overlay (triggers auto-rerun via createEffect on spec), and — on
   * the transition from "none" to "pkcs7" — swaps the default FIPS vector
   * for the short "apple" so the new pad frame shows up immediately.
   *
   * We only swap the input bytes if the field currently holds the canonical
   * FIPS vector (untouched first-load state). If the user already typed
   * something else, we leave it alone — clobbering their edit on a selector
   * change would be hostile.
   */
  const changePadding = (next: PaddingScheme): void => {
    const prev = padding();
    if (prev === next) return;
    if (next === "pkcs7" && mode() === "encrypt") {
      const currentBytes = tryParseBytes(inputText(), fmt());
      if (currentBytes && bytesEqual(currentBytes, DEFAULT_PT_BYTES)) {
        setInputText(formatBytes(DEFAULT_PKCS7_PT_BYTES, fmt()));
      }
    } else if (next === "none" && mode() === "encrypt") {
      const currentBytes = tryParseBytes(inputText(), fmt());
      if (currentBytes && bytesEqual(currentBytes, DEFAULT_PKCS7_PT_BYTES)) {
        setInputText(formatBytes(DEFAULT_PT_BYTES, fmt()));
      }
    }
    setPadding(next);
  };

  // Reactive derived values for the trace view.
  const frameIndex = useFrameIndex();
  const version = useTraceVersion();

  const currentFrame = createMemo(() => {
    void version();
    return getTrace()?.frames[frameIndex()] ?? null;
  });

  /**
   * Format the final state's bytes through the active byte format. Accepts
   * both matrix and bytes final-state shapes — bytes shows up when the
   * decrypt+pkcs7 path strips the padding at the end.
   */
  const outputText = createMemo(() => {
    void version();
    const t = getTrace();
    if (!t) return null;
    const s = t.finalState;
    if (s.shape !== "matrix4x4-bytes" && s.shape !== "bytes") return null;
    return formatBytes(s.bytes, fmt());
  });

  // Phase 2b — overlay: look up the same-stepId frame from the run just
  // before the current one. We memoize on (history, currentFrame.stepId)
  // so a scrub through the trace re-uses the same snapshot's frames
  // without re-walking them on every render.
  const history = useHistory();
  const showPrev = useShowPreviousRun();
  const previousRunFrame = createMemo<TraceFrame | null>(() => {
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
        <label>
          padding
          <select
            value={padding()}
            onChange={(e) => changePadding(e.currentTarget.value as PaddingScheme)}
            title="Padding scheme applied at the start of encrypt / end of decrypt"
          >
            <For each={PADDING_SCHEME_OPTIONS}>
              {(scheme) => <option value={scheme}>{PADDING_SCHEME_LABELS[scheme]}</option>}
            </For>
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
        <button
          type="button"
          onClick={() => setExplorerOpen(true)}
          disabled={historyCount() === 0}
          title="Open the Run Explorer to compare snapshots side by side"
        >
          compare runs ({historyCount()})
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

              {/* State view, dispatched by (stateBefore.shape, stateAfter.shape):
                  - both matrix       → MatrixView (today's path)
                  - both bytes        → BytesView (pad/unpad frames)
                  - mixed (boundary)  → side-by-side inline render so the
                                        user can see the shape transition. */}
              <FrameStateView frame={frame()} previousRunFrame={previousRunFrame()} />

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

      {/* ─── Run Explorer modal (Phase 2c). Renders as a sibling so
            it can position fixed across the entire viewport. */}
      <RunExplorerModal isOpen={explorerOpen} onClose={() => setExplorerOpen(false)} />
    </div>
  );
};

/**
 * Shape-aware render dispatch for one frame's before/after state. Pulled
 * out of App so the four-way branch is readable.
 */
const FrameStateView = (props: {
  frame: TraceFrame;
  previousRunFrame: TraceFrame | null;
}) => {
  const before = () => props.frame.stateBefore;
  const after = () => props.frame.stateAfter;
  const prevAfter = () => props.previousRunFrame?.stateAfter ?? null;

  return (
    <Show
      when={before().shape === "matrix4x4-bytes" && after().shape === "matrix4x4-bytes"}
      fallback={
        <Show
          when={before().shape === "bytes" && after().shape === "bytes"}
          fallback={<MixedShapeView before={before()} after={after()} />}
        >
          <BytesView
            before={before() as BytesState}
            after={after() as BytesState}
            previousAfter={prevAfter()}
          />
        </Show>
      }
    >
      <MatrixView
        before={before() as MatrixState}
        after={after() as MatrixState}
        previousAfter={prevAfter()}
      />
    </Show>
  );
};

/**
 * Boundary-frame view for shape transitions (BytesState ↔ MatrixState).
 * Renders the bytes side as a single row and the matrix side as a 4×4 grid,
 * side-by-side, so the user can see the layout swap (which is what
 * load-block and store-block represent). The byte values themselves don't
 * change across these frames — only the shape does.
 */
const MixedShapeView = (props: { before: State; after: State }) => {
  return (
    <div class="mixed-shape-view">
      <SingleStateView title="before" state={props.before} />
      <SingleStateView title="after" state={props.after} />
    </div>
  );
};

const SingleStateView = (props: { title: string; state: State }) => {
  const fmt = useByteFormat();

  // Derive cell descriptors per shape. Reading props.state inside the
  // memos keeps the views reactive to scrubber changes.
  const bytesCells = createMemo(() => {
    if (props.state.shape !== "bytes") return null;
    const bytes = props.state.bytes;
    return { length: bytes.length, indices: Array.from({ length: bytes.length }, (_, i) => i) };
  });

  const matrixCells = createMemo(() => {
    if (props.state.shape !== "matrix4x4-bytes") return null;
    const out: { row: number; col: number; idx: number }[] = [];
    for (let c = 0; c < 4; c++) {
      for (let r = 0; r < 4; r++) {
        out.push({ row: r, col: c, idx: r + 4 * c });
      }
    }
    return out;
  });

  return (
    <Show
      when={matrixCells()}
      fallback={
        <Show when={bytesCells()}>
          {(getCells) => (
            <div class="bytes-row-block">
              <div class="grid-title">
                {props.title}
                <span class="bytes-row-count"> ({getCells().length} bytes)</span>
              </div>
              <div class="bytes-row">
                <For each={getCells().indices}>
                  {(i) => (
                    <div class="bytes-cell">
                      {/* Inline format read so a format toggle re-renders. */}
                      {formatByte((props.state as BytesState).bytes[i] ?? 0, fmt())}
                    </div>
                  )}
                </For>
              </div>
            </div>
          )}
        </Show>
      }
    >
      {(getCells) => (
        <div class="grid-block">
          <div class="grid-title">{props.title} (matrix)</div>
          <div class="grid">
            <For each={getCells()}>
              {(cell) => (
                <div
                  class="cell"
                  style={{
                    "grid-row": `${cell.row + 1}`,
                    "grid-column": `${cell.col + 1}`,
                  }}
                >
                  {formatByte((props.state as MatrixState).bytes[cell.idx] ?? 0, fmt())}
                </div>
              )}
            </For>
          </div>
        </div>
      )}
    </Show>
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

/** Returns null if the field doesn't parse cleanly — used by `changePadding`
 * to test whether the input is still the canonical default before swapping
 * it for the scheme-appropriate default. */
const tryParseBytes = (text: string, fmt: ByteFormat): Uint8Array | null => {
  try {
    return parseBytes(text, fmt);
  } catch {
    return null;
  }
};

const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
};

/** Build the friendly length-mismatch error shown when the input isn't in
 * the allowed [min, max] range for (mode, scheme). The hint cites the
 * scheme so the user can connect "why 0..15" to "PKCS#7 always adds ≥1 byte
 * to fill the block." */
const formatLengthError = (
  mode: "encrypt" | "decrypt",
  scheme: PaddingScheme,
  got: number,
  min: number,
  max: number,
): string => {
  const label = mode === "encrypt" ? "plaintext" : "ciphertext";
  const range = min === max ? `${min} bytes` : `${min}–${max} bytes`;
  if (mode === "encrypt" && scheme === "pkcs7") {
    return `${label}: PKCS#7 input must be ${range}; got ${got}. (A ${max + 1}-byte input would need a second padding block — multi-block modes are not yet supported.)`;
  }
  if (mode === "decrypt") {
    return `${label}: must be exactly ${min} bytes (one AES block); got ${got}.`;
  }
  return `${label}: must be ${range}; got ${got}.`;
};
