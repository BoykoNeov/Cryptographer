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
import { BlockBadge } from "./components/BlockBadge";
import { BytesView } from "./components/BytesView";
import { MatrixView } from "./components/MatrixView";
import { ParamEditor } from "./components/ParamEditor";
import { RunExplorerModal } from "./components/RunExplorerModal";
import { StepDescription } from "./components/StepDescription";
import { StepList } from "./components/StepList";
import { StepStrip } from "./components/StepStrip";
import { TraceTimeline } from "./components/TraceTimeline";
import { clearDirty, setAutoRerun, setDirty, useAutoRerun, useDirty } from "./stores/auto-rerun";
import {
  CIPHER_LABELS,
  CIPHER_OPTIONS,
  type Cipher,
  DEFAULT_KEY_BYTES_BY_CIPHER,
  DEFAULT_PT_BYTES_BY_CIPHER,
  isAesCipher,
  useCipher,
} from "./stores/cipher";
import {
  CIPHER_MODE_LABELS,
  type CipherMode,
  SUPPORTED_CIPHER_MODES,
  isCipherModeSupported,
  useCipherMode,
} from "./stores/cipher-mode";
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
import {
  resetSpec,
  setCipher,
  setCipherMode,
  setMode,
  setPadding,
  useMode,
  useSpec,
} from "./stores/spec";
import { getTrace, setTrace, useFrameIndex, useTraceVersion } from "./stores/trace";
import "./app.css";

// Per-cipher default plaintext lives in stores/cipher.ts (mirrors the
// per-cipher default key). AES uses the FIPS-197 sequential 16-byte vector;
// Speck uses the Beaulieu et al. 2013 KAT plaintext in the appropriate
// byte convention. The shared 16-byte AES default is grabbed below for the
// "currently holds a recognisable default?" check in changePadding.
const DEFAULT_AES_PT_BYTES = DEFAULT_PT_BYTES_BY_CIPHER["aes-128"];
// When the user reloads with a non-`none` padding scheme that caps input
// below 16 bytes (pkcs7 + iso7816-4), the FIPS vector would immediately
// fail the length check. Default to a short, visible word so the trace
// produces a clean pad/unpad frame on first Run. The bytes are the ASCII
// codepoints for "apple". AES-only — Speck has no padding scheme today.
const DEFAULT_SHORT_PT_BYTES = new Uint8Array([0x61, 0x70, 0x70, 0x6c, 0x65]);

// How long after the last spec edit before we re-run the cipher. 200ms is
// long enough that fast typing on 256 S-box cells doesn't cause a re-run
// on every keystroke, but short enough to feel immediate.
const AUTO_RERUN_DEBOUNCE_MS = 200;

export const App = () => {
  const spec = useSpec();
  const mode = useMode();
  const fmt = useByteFormat();
  const padding = usePaddingScheme();
  const cipher = useCipher();
  const cipherMode = useCipherMode();

  // Inputs — kept as strings (in whatever the current byte format is) so
  // the user can paste partial input without the field fighting them
  // mid-type. We validate on run. Initial plaintext varies by cipher AND
  // by initial padding scheme. For non-AES ciphers (Speck), we use the
  // cipher's KAT plaintext directly — padding isn't supported yet.
  // For AES, schemes that cap encrypt input below 16 bytes (pkcs7 +
  // iso7816-4) get the short "apple" so the user sees padding working
  // immediately on a fresh reload. Initial key varies by cipher.
  const initialLimits = paddingLimits(mode(), padding(), cipher(), cipherMode());
  const initialPtBytes =
    isAesCipher(cipher()) && mode() === "encrypt" && initialLimits.max < 16
      ? DEFAULT_SHORT_PT_BYTES
      : DEFAULT_PT_BYTES_BY_CIPHER[cipher()];
  const [inputText, setInputText] = createSignal(formatBytes(initialPtBytes, fmt()));
  const [keyText, setKeyText] = createSignal(
    formatBytes(DEFAULT_KEY_BYTES_BY_CIPHER[cipher()], fmt()),
  );
  const [error, setError] = createSignal<string | null>(null);

  // Has the user successfully run the cipher at least once? If yes, spec
  // edits trigger an auto-rerun. If no, edits do nothing — we'd just be
  // throwing parse errors at the user before they've even hit "run."
  const [hasRunOnce, setHasRunOnce] = createSignal(false);

  // Auto/manual rerun preference + dirty flag (May 2026). Two pieces of
  // state with different lifetimes: the *preference* is persisted in
  // localStorage; the *dirty flag* is session-only and just tracks whether
  // there are unrun edits relative to the most recent successful run.
  const autoRerun = useAutoRerun();
  const dirty = useDirty();

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
      const { min, max } = paddingLimits(mode(), padding(), cipher(), cipherMode());
      if (inputBytes.length < min || inputBytes.length > max) {
        throw new Error(
          formatLengthError(mode(), padding(), cipher(), cipherMode(), inputBytes.length, min, max),
        );
      }
      // Multi-block ECB/CBC require block-aligned input on decrypt OR when
      // the padding scheme is "none" on encrypt. Catch it here with a
      // friendly error rather than letting split-blocks throw a
      // runtime-internals error from inside the iterate loop.
      const needsAlignment =
        (cipherMode() === "ecb" || cipherMode() === "cbc") &&
        (mode() === "decrypt" || padding() === "none");
      if (needsAlignment && inputBytes.length % 16 !== 0) {
        throw new Error(
          `${inputLabel()}: must be a multiple of 16 bytes (whole AES blocks); got ${inputBytes.length}.`,
        );
      }

      // Key length depends on the active cipher: 16 (AES-128) / 24 (192) /
      // 32 (256). The spec carries this in inputs.key.byteLength — read it
      // off the live spec rather than threading the cipher signal in.
      let keyBytes: Uint8Array;
      try {
        keyBytes = parseBytesWithLength(keyText(), fmt(), spec().inputs.key.byteLength);
      } catch (e) {
        throw new Error(`key: ${e instanceof Error ? e.message : String(e)}`);
      }

      // Initial state shape: read directly from the active spec. For AES+
      // padding the spec declares `inputs.plaintext.shape === "bytes"` so
      // pad/load can wrap it; for AES+none and decrypt it's a 16-byte
      // matrix; for Speck (no padding overlay) it's always bytes (4-byte
      // block). The spec is the single source of truth, so we no longer
      // hardcode the (mode, padding) heuristic here.
      const initialState: State =
        spec().inputs.plaintext.shape === "bytes"
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
      // The new trace is in sync with the live spec, so any "edits pending"
      // banner from manual mode is now stale. Clear it. (Auto-rerun mode
      // never sets dirty, so this is a no-op there.)
      clearDirty();
    } catch (err) {
      setError(err instanceof Error ? err.message : String(err));
    }
  };

  // Re-run on spec edit, but only when the user has opted into auto-rerun
  // mode (the default). In manual mode we instead flip the dirty flag so
  // the UI can show an "edits pending — click Run" banner, preserving the
  // prior run snapshot for comparison in the Run Explorer until the user
  // deliberately commits the batched edits.
  //
  // `on(spec, ...)` runs ONLY when the spec signal changes, not on initial
  // setup — important because neither mode should fire before the user
  // has hit Run once.
  createEffect(
    on(
      spec,
      () => {
        if (!hasRunOnce()) return;
        if (!autoRerun()) {
          // Manual mode: just record that there are unrun edits. No
          // debounce, no cipher call — the user will press Run.
          setDirty(true);
          return;
        }
        // Auto mode (default): same debounced re-run as before. 200ms is
        // long enough that fast S-box typing doesn't hammer the runtime
        // but short enough to feel immediate.
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
   * new overlay (triggers auto-rerun via createEffect on spec), and — when
   * the user's current input would no longer fit the new scheme's length
   * range — swaps in a sensible default so the next Run produces a clean
   * frame instead of a length-mismatch error.
   *
   * Swap policy: only touches the input if it currently holds one of our
   * two canonical defaults (FIPS-197 16-byte vector, or "apple"). If the
   * user typed anything else, leave it alone — clobbering their in-flight
   * edit on a selector change would be hostile. They'll see the friendly
   * length error on the next Run.
   *
   * Generalized over the four (and future) schemes: the decision hangs on
   * the new scheme's max length, not on the scheme name. So zero-pad (max
   * 16) keeps the FIPS vector; pkcs7/iso7816-4 (max 15) force the short
   * "apple"; `none` (min/max 16) forces the FIPS vector back if "apple"
   * is currently in the field.
   */
  /**
   * Switch the active AES variant (128/192/256). Routes through the spec
   * store, which replaces the spec and re-applies the active padding.
   * Then swap the key field IF it currently holds the previous cipher's
   * canonical default — mirroring the swap policy in `changePadding`. A
   * user-typed key is never clobbered; the user will see a friendly length
   * error on the next Run if they don't update it manually.
   */
  const changeCipher = (next: Cipher): void => {
    const prev = cipher();
    if (prev === next) return;
    // Key field: swap to the new cipher's default only if it currently
    // holds the previous cipher's default. User-typed keys are left alone
    // (the user will see a friendly length error on Run if the byte count
    // doesn't match the new cipher's `inputs.key.byteLength`).
    const currentKey = tryParseBytes(keyText(), fmt());
    if (currentKey && bytesEqual(currentKey, DEFAULT_KEY_BYTES_BY_CIPHER[prev])) {
      setKeyText(formatBytes(DEFAULT_KEY_BYTES_BY_CIPHER[next], fmt()));
    }
    // Plaintext field: same policy. AES↔Speck flips change the block size
    // (16↔4 bytes), so a literal value-equal default carry-over is the
    // right trigger for an auto-swap. A user-typed arbitrary value stays.
    // Also covers AES↔AES (no-op for "00112233...ff" which is the shared
    // FIPS-197 default across all three AES variants) and Speck-BE↔Speck-LE
    // (4 bytes either way, but the byte sequence differs by convention).
    const currentPt = tryParseBytes(inputText(), fmt());
    if (currentPt && bytesEqual(currentPt, DEFAULT_PT_BYTES_BY_CIPHER[prev])) {
      setInputText(formatBytes(DEFAULT_PT_BYTES_BY_CIPHER[next], fmt()));
    }
    setCipher(next);
  };

  const changePadding = (next: PaddingScheme): void => {
    const prev = padding();
    if (prev === next) return;
    if (mode() === "encrypt") {
      const currentBytes = tryParseBytes(inputText(), fmt());
      if (currentBytes) {
        const nextLimits = paddingLimits(mode(), next, cipher(), cipherMode());
        const fits = currentBytes.length >= nextLimits.min && currentBytes.length <= nextLimits.max;
        if (!fits) {
          if (bytesEqual(currentBytes, DEFAULT_AES_PT_BYTES) && nextLimits.max < 16) {
            setInputText(formatBytes(DEFAULT_SHORT_PT_BYTES, fmt()));
          } else if (bytesEqual(currentBytes, DEFAULT_SHORT_PT_BYTES) && nextLimits.min === 16) {
            setInputText(formatBytes(DEFAULT_AES_PT_BYTES, fmt()));
          }
        }
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

  // Total block count across the current trace (for the BlockBadge "of N"
  // suffix). Counts unique blockIndex values rather than reading
  // aux["blockCount"] so it works for any future iterate-using spec.
  // Returns 1 when no frames are tagged with blockIndex (single-block).
  const blockCount = createMemo<number>(() => {
    void version();
    const t = getTrace();
    if (!t) return 1;
    let maxIdx = -1;
    for (const f of t.frames) {
      if (f.blockIndex !== undefined && f.blockIndex > maxIdx) maxIdx = f.blockIndex;
    }
    return maxIdx < 0 ? 1 : maxIdx + 1;
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
          cipher
          <select
            value={cipher()}
            onChange={(e) => changeCipher(e.currentTarget.value as Cipher)}
            title="AES variant — 128/192/256 differ in key length and round count"
          >
            <For each={CIPHER_OPTIONS}>{(c) => <option value={c}>{CIPHER_LABELS[c]}</option>}</For>
          </select>
        </label>
        <label>
          mode of operation
          <select
            value={cipherMode()}
            onChange={(e) => setCipherMode(e.currentTarget.value as CipherMode)}
            disabled={!isAesCipher(cipher())}
            title={
              isAesCipher(cipher())
                ? "Block-cipher mode of operation. 'single block' keeps the canonical FIPS-197 single-block trace. ECB encrypts each block independently (educational baseline — the Tux-image leak). CBC/CTR ship in later phases. AES-128 is the only variant with the multi-block factories wired up today — AES-192/256 ECB lands in Phase 4."
                : "Modes of operation are AES-only in this build; Speck runs as a single-block cipher."
            }
          >
            <option value="single-block">{CIPHER_MODE_LABELS["single-block"]}</option>
            <option
              value="ecb"
              disabled={
                !(SUPPORTED_CIPHER_MODES as readonly string[]).includes("ecb") ||
                !isCipherModeSupported(cipher(), "ecb")
              }
            >
              {CIPHER_MODE_LABELS.ecb}
              {isAesCipher(cipher()) && !isCipherModeSupported(cipher(), "ecb")
                ? " (AES-128 only in Phase 1)"
                : ""}
            </option>
            <option
              value="cbc"
              disabled={!(SUPPORTED_CIPHER_MODES as readonly string[]).includes("cbc")}
            >
              {CIPHER_MODE_LABELS.cbc} (coming Phase 2)
            </option>
            <option
              value="ctr"
              disabled={!(SUPPORTED_CIPHER_MODES as readonly string[]).includes("ctr")}
            >
              {CIPHER_MODE_LABELS.ctr} (coming Phase 3)
            </option>
          </select>
        </label>
        <label>
          padding
          <select
            value={padding()}
            onChange={(e) => changePadding(e.currentTarget.value as PaddingScheme)}
            disabled={!isAesCipher(cipher())}
            title={
              isAesCipher(cipher())
                ? "Padding scheme applied at the start of encrypt / end of decrypt"
                : "Padding is AES-only in this build — the overlay's load-block step assumes a 16-byte matrix. The non-AES cipher uses its natural block size as the input length."
            }
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
        {/* Auto/manual rerun toggle. When ON, spec edits re-run the cipher
            after a 200ms debounce. When OFF, edits just light up the
            "edits pending" banner below and the user commits them with
            Run — useful when you want to batch several S-box tweaks into
            one snapshot for the Run Explorer instead of having each edit
            push the prior run off the 5-deep history buffer. */}
        <label
          class="auto-rerun-toggle"
          title="Re-run the cipher automatically when you edit the spec"
        >
          <input
            type="checkbox"
            checked={autoRerun()}
            onChange={(e) => setAutoRerun(e.currentTarget.checked)}
          />
          auto-rerun
        </label>
        {/* Manual mode only: surface unrun spec edits so the user sees
            their tweaks haven't taken effect yet. The banner clears on
            the next successful run. Hidden in auto-rerun mode (dirty is
            never set). Lives inside `.inputs` (flex wrap row) with
            full-width basis so it lands on its own line below the Run
            button — visually adjacent to the action that clears it. */}
        <Show when={dirty()}>
          {/* Native <output> carries an implicit `role="status"` so screen
              readers announce the change without us repeating the role. */}
          <output class="pending-banner">
            edits pending — click <strong>run</strong> to update the trace
          </output>
        </Show>
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

              {/* Multi-block context chip. Only renders when the current
                  frame belongs to an iterate node (blockIndex is set). */}
              <BlockBadge blockIndex={frame().blockIndex} blockCount={blockCount()} />

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
 * the allowed [min, max] range. The hint cites the scheme (and, for
 * multi-block, the cipher mode) so the user can connect "why 0..15" to
 * "PKCS#7 always adds ≥1 byte to fill the block" and similar reasoning. */
const formatLengthError = (
  mode: "encrypt" | "decrypt",
  scheme: PaddingScheme,
  cipher: Cipher,
  cipherMode: CipherMode,
  got: number,
  min: number,
  max: number,
): string => {
  const label = mode === "encrypt" ? "plaintext" : "ciphertext";
  const range = min === max ? `${min} bytes` : `${min}–${max} bytes`;

  // Non-AES ciphers (today: Speck32/64) take a fixed single-block input.
  if (!isAesCipher(cipher)) {
    return `${label}: must be exactly ${min} bytes (one ${CIPHER_LABELS[cipher]} block); got ${got}.`;
  }

  // Multi-block modes (ECB/CBC/CTR) — cite the cap rather than "second
  // padding block" since multi-block has no such limit. The cap is the
  // UI's MAX_BLOCKS_UI; the user can raise it if they want more.
  if (cipherMode === "ecb" || cipherMode === "cbc") {
    if (mode === "decrypt") {
      return `${label}: ${cipherMode.toUpperCase()} ciphertext must be a whole-block multiple in ${range}; got ${got}. (Cap is the UI's MAX_BLOCKS_UI for trace browsability — raise to extend.)`;
    }
    const schemeLabel = scheme === "none" ? "no padding" : scheme.toUpperCase();
    return `${label}: ${cipherMode.toUpperCase()} + ${schemeLabel} accepts ${range}; got ${got}. (Cap is the UI's MAX_BLOCKS_UI for trace browsability — raise to extend.)`;
  }
  if (cipherMode === "ctr") {
    return `${label}: AES-CTR accepts ${range}; got ${got}. (No padding needed; cap is the UI's MAX_BLOCKS_UI for trace browsability.)`;
  }

  // Single-block AES: today's behavior with scheme-specific hints.
  if (mode === "decrypt") {
    return `${label}: must be exactly ${min} bytes (one AES block); got ${got}.`;
  }
  switch (scheme) {
    case "pkcs7":
      return `${label}: PKCS#7 input must be ${range}; got ${got}. (A ${max + 1}-byte input would need a second padding block — switch to ECB/CBC mode for multi-block input.)`;
    case "iso7816-4":
      return `${label}: ISO 7816-4 input must be ${range}; got ${got}. (Like PKCS#7, this scheme always appends at least one byte — the 0x80 sentinel — so a ${max + 1}-byte input would need a second block. Switch to ECB/CBC mode for multi-block input.)`;
    case "zero-pad":
      if (got < min) {
        return `${label}: Zero-pad input must be ${range}; got ${got}. (Length 0 would produce an empty padded block, which can't be loaded into the AES state.)`;
      }
      return `${label}: Zero-pad input must be ${range}; got ${got}. (A ${max + 1}-byte input would need a second padding block — switch to ECB/CBC mode for multi-block input.)`;
    case "none":
      return `${label}: must be ${range}; got ${got}.`;
  }
};
