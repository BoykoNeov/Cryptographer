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
  CURRENT_SCHEMA_VERSION,
  type CipherDocument,
  parseDocument,
  serializeDocument,
} from "@/core/document";
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
import { APP_VERSION } from "@/version";
import {
  For,
  Match,
  Show,
  Switch,
  createEffect,
  createMemo,
  createSignal,
  on,
  onCleanup,
  onMount,
} from "solid-js";
import { BlockBadge } from "./components/BlockBadge";
import { BytesView } from "./components/BytesView";
import { GraphView } from "./components/GraphView";
import { IvInput } from "./components/IvInput";
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
import { useIvBytes } from "./stores/iv";
import { installKeyboardShortcuts } from "./stores/keyboard";
import { getLayoutForSpec, hasUserLayout, setLayoutForSpec } from "./stores/layout";
import {
  PADDING_SCHEME_LABELS,
  PADDING_SCHEME_OPTIONS,
  type PaddingScheme,
  paddingLimits,
  usePaddingScheme,
} from "./stores/padding";
import { registry } from "./stores/registry";
import {
  isCustomSpec,
  resetSpec,
  setCipher,
  setCipherMode,
  setMode,
  setPadding,
  setSpecFromDocument,
  useMode,
  useSpec,
} from "./stores/spec";
import {
  getTrace,
  setTrace,
  useFrameIndex,
  useSelectedStepId,
  useTraceVersion,
} from "./stores/trace";
import {
  buildShareHash,
  decodeHashToDocument,
  encodeDocumentToHash,
  extractHashPayload,
} from "./stores/url-share";
import {
  ALL_VIEW_MODES,
  VIEW_MODE_LABELS,
  type ViewMode,
  setViewMode,
  useViewMode,
} from "./stores/view-mode";
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
  const ivBytes = useIvBytes();
  const viewMode = useViewMode();

  // True when the live spec has diverged from the canonical default for
  // the current selectors (param edits, palette inserts, deletions). Drives
  // the "Custom (was AES-128)" indicator in the header + dropdown, and the
  // visibility of the reset-to-canonical button next to the cipher selector.
  // Memoised so the dropdown's per-option label callback doesn't recompute
  // the deep-equal walk on every render.
  const isCustom = createMemo(() => isCustomSpec());

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

  // Slice 5 of the 2D editor plan — Save/Load.
  //
  // The checkbox is a binary toggle per the locked-in design (memory
  // entry [[project-2d-editor-plan]]): off → spec-only file (no session
  // field at all); on → full session (selectors + inputs + key bytes).
  // Splitting selectors off from bytes would be a third variant; the user
  // signed off on two. Default off so the first impulse-save doesn't leak
  // plaintext bytes to disk.
  const [includeSession, setIncludeSession] = createSignal(false);
  // Ref to the hidden <input type="file"> so the [Load] button can trigger
  // the OS file picker programmatically.
  let fileInputRef: HTMLInputElement | undefined;

  // Slice 7 — URL hash share feedback. The Share button copies the
  // generated link to the clipboard and flips this signal so the UI can
  // show "Copied!" briefly; cleared by setTimeout. Using a signal (vs.
  // inline DOM mutation) keeps the rendering reactive and SSR-safe.
  const [shareStatus, setShareStatus] = createSignal<{
    readonly kind: "success" | "error";
    readonly message: string;
  } | null>(null);
  // Stable closure variable for the share-status auto-clear timer. Tracked
  // here (not via onCleanup inside the async handler — onCleanup requires
  // a current reactive owner, which event handlers don't have) so a quick
  // double-share doesn't leave the first timer racing the second.
  let shareStatusTimer: ReturnType<typeof setTimeout> | null = null;
  onCleanup(() => {
    if (shareStatusTimer !== null) clearTimeout(shareStatusTimer);
  });

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
      // CBC seeds the IV from the dedicated `iv` store (the IvInput
      // field below). The store always holds exactly 16 bytes — its
      // setter enforces the length and the randomize button generates
      // the right size — so we can drop straight into aux.
      if (cipherMode() === "cbc") {
        initialAux.set("iv", new Uint8Array(ivBytes()));
      }
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

  /**
   * Build the serialized JSON text for a "Save" action against the
   * current store state. Pure-ish: reads signals + the includeSession
   * checkbox, returns the text. Factored out so tests can drive Save
   * without mocking `Blob` + `URL.createObjectURL` + the synthesized
   * `<a>` click — they just call this and inspect the result.
   *
   * Two shapes:
   *   • includeSession=false → `{ schemaVersion, spec, metadata? }`.
   *     Just the cipher topology; no selectors, no plaintext/key. The
   *     "share my custom AES variant" minimum.
   *   • includeSession=true → adds `session` with the four selector
   *     values + active byteFormat + (if parseable) inputBytes + keyBytes.
   *     Reloading this file rebuilds the user's view exactly.
   *
   * `inputBytes` / `keyBytes` are best-effort: if the current text in the
   * fields doesn't parse cleanly under the active byte format (mid-edit
   * garbage), we omit them. The file is still valid — `session.inputBytes`
   * is optional in the schema — and the loading user will just see their
   * own input/key default on load. Better than refusing to save.
   */
  const buildSaveText = (): string => {
    // `createdAt` only fires when include-session is on, so spec-only
    // saves are byte-stable: the same custom spec saved twice produces
    // identical files. That matters for Slice 7 (URL hash share), which
    // hashes the serialized form — stamping a timestamp on the spec-only
    // path would mean the same spec produces a different shareable URL
    // every session. With include-session on, the session bytes are
    // already session-specific, so adding createdAt costs no determinism.
    // Layout sidecar is included only when the user has dragged something
    // OR collapsed a container (`hasUserLayout`). Empty/null layouts must
    // be OMITTED — otherwise the same un-customized spec produces different
    // bytes than a fresh save (the Slice 5 byte-stability test pins this).
    const layout = getLayoutForSpec(spec().id);
    const doc: CipherDocument = {
      schemaVersion: CURRENT_SCHEMA_VERSION,
      spec: spec(),
      ...(hasUserLayout(layout) && layout ? { layout } : {}),
      ...(includeSession()
        ? {
            session: buildSessionSnapshot(),
            // `appVersion` stamps which build of Cryptographer produced this
            // file — useful forensically when a v0.5 user opens a v0.2 file.
            // Only emitted on the session-on branch alongside `createdAt`;
            // the spec-only branch stays byte-stable so the Slice 7 URL hash
            // remains deterministic across builds.
            metadata: { createdAt: Date.now(), appVersion: APP_VERSION },
          }
        : {}),
    };
    return serializeDocument(doc);
  };

  const buildSessionSnapshot = () => {
    // Best-effort bytes capture. Same try/catch shape as
    // `tryParseBytes`/`reformatTextOrKeep` elsewhere in this file.
    const input = tryParseBytes(inputText(), fmt());
    const key = tryParseBytes(keyText(), fmt());
    // IV included only when the active mode uses one. Saving an IV for
    // single-block / ECB would be confusing — the spec doesn't read
    // aux[iv] there, so the value would silently round-trip but mean
    // nothing.
    const includeIv = cipherMode() === "cbc";
    return {
      mode: mode(),
      cipher: cipher(),
      cipherMode: cipherMode(),
      padding: padding(),
      byteFormat: fmt(),
      ...(input ? { inputBytes: Array.from(input) } : {}),
      ...(key ? { keyBytes: Array.from(key) } : {}),
      ...(includeIv ? { ivBytes: Array.from(ivBytes()) } : {}),
    } as const;
  };

  /**
   * Trigger a file download for the current document. Uses the modern
   * Blob + URL.createObjectURL + synthesized `<a download>` dance —
   * standard pattern for client-side file output. Filename includes the
   * spec id and today's date so the user's downloads folder stays
   * navigable even if they save many variants.
   */
  const saveDocument = (): void => {
    const text = buildSaveText();
    const blob = new Blob([text], { type: "application/json" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `${spec().id}-${ymdToday()}.cipher.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  /**
   * Slice 7 — Share. Build the current document, encode it as `#doc=…`,
   * concatenate with the page's origin + path, and write the resulting
   * URL to the clipboard. Async because both `encodeDocumentToHash`
   * (CompressionStream-driven) and `navigator.clipboard.writeText` return
   * promises.
   *
   * Honors the same `includeSession` toggle as Save — the user opts into
   * leaking plaintext bytes the same way for both surfaces. Spec-only
   * shares are byte-stable, so the same URL works across sessions; the
   * Slice 7 test pins this property the same way Slice 5 pins it for the
   * file path.
   *
   * Success flips `shareStatus` to a brief "Copied!" inline message;
   * clipboard failures (write blocked by browser policy, e.g. in HTTP
   * dev contexts) fall through to a friendly error so the user can copy
   * the URL manually from the field shown below.
   */
  const shareDocument = async (): Promise<void> => {
    try {
      const doc = parseDocument(buildSaveText());
      if (!doc.ok) {
        setShareStatus({
          kind: "error",
          message: `could not build share document: ${doc.error}`,
        });
        return;
      }
      const encoded = await encodeDocumentToHash(doc.doc);
      const url = `${window.location.origin}${window.location.pathname}${buildShareHash(encoded)}`;
      try {
        await navigator.clipboard.writeText(url);
        setShareStatus({ kind: "success", message: `link copied (${encoded.length} chars)` });
      } catch (clipErr) {
        // Clipboard write can be blocked in non-secure contexts (HTTP) or
        // by user permission denial. The URL itself encoded fine; surface
        // it so the user can copy it from the address bar manually.
        window.history.replaceState(null, "", buildShareHash(encoded));
        setShareStatus({
          kind: "error",
          message: `clipboard write blocked — URL placed in address bar: ${errMessage(clipErr)}`,
        });
      }
    } catch (e) {
      setShareStatus({ kind: "error", message: `share failed: ${errMessage(e)}` });
    }
    // Auto-clear the inline status after 3s so the toolbar doesn't carry
    // a stale "Copied!" forever. Clear any pending prior timer first so
    // a fast double-share doesn't reset the new status early.
    if (shareStatusTimer !== null) clearTimeout(shareStatusTimer);
    shareStatusTimer = setTimeout(() => {
      setShareStatus(null);
      shareStatusTimer = null;
    }, 3000);
  };

  /**
   * Slice 7 — boot hook. On first mount, if the URL hash carries a `doc=…`
   * payload, decode it asynchronously and apply via `applyDocument`. On
   * success, clear the hash from the address bar (replaceState, not
   * pushState — we don't want a back-button bounce to the shared URL).
   * On failure, keep the hash so the user can debug or report it.
   *
   * Stores have already hydrated from localStorage at module-import time
   * by the time onMount runs; `setSpecFromDocument` deliberately bypasses
   * the defaults table, so the URL's literal spec wins over whatever
   * localStorage held.
   */
  onMount(() => {
    if (typeof window === "undefined") return; // SSR / non-browser test env
    const payload = extractHashPayload(window.location.hash);
    if (payload === null || payload.length === 0) {
      // No URL-hash doc to decode. Fire a boot-time run with the default
      // selectors so a trace exists before the user touches anything.
      //
      // This fixes the trace-coupling bug (`docs/plans/trace-coupling-bug-
      // fix.md`): without a trace, palette drops produced no warning
      // glyphs (validateGraph walks frames), the ParamEditor couldn't
      // resolve a clicked leaf (it took a TraceFrame, not a stepId), and
      // the replicate-fanout toggle had no aux edges to operate on.
      // Boot-running with the canonical default spec makes the graph view
      // immediately interactive on app load.
      //
      // The hash-decode branch below already calls `run()` via
      // `applyDocument`, so we only need this in the no-hash path —
      // doubling up would be wasted work even though `pushSnapshot` dedups.
      run();
      return;
    }
    void (async () => {
      const result = await decodeHashToDocument(payload);
      if (!result.ok) {
        setError(`Could not load shared link: ${result.error}`);
        return;
      }
      applyDocument(result.doc);
      // Strip the hash from the address bar so a refresh doesn't re-apply
      // the shared doc (which would clobber any edits the user made since
      // the initial load).
      window.history.replaceState(null, "", window.location.pathname + window.location.search);
    })();
  });

  /**
   * Apply a parsed CipherDocument to the live stores: layout sidecar (if
   * any), spec + selectors via `setSpecFromDocument`, session inputs/key
   * (formatted under the doc's byteFormat), then run synchronously so the
   * trace lands immediately. Shared by file-load (Slice 5) and URL-share
   * load (Slice 7) so both paths go through one boundary.
   *
   * Three orderings that have to be right and would silently regress if a
   * refactor splits them:
   *   1. **Layout BEFORE spec.** GraphView reads layout reactively keyed by
   *      the active spec's id; we want its first re-derive after the spec
   *      change to read the new layout, not blink through auto-layout for
   *      a frame.
   *   2. **byteFormat lands inside `setSpecFromDocument` BEFORE we call
   *      formatBytes here.** The Slice 5 byteFormat-hydration-order test
   *      pins this — if a refactor splits the setter, restored bytes would
   *      render in the old format.
   *   3. **`run()` synchronously** so the trace appears immediately. The
   *      200ms `on(spec)` debounce will also fire (spec changed); its
   *      duplicate run is harmless because pushSnapshot dedups.
   */
  const applyDocument = (doc: CipherDocument): void => {
    setLayoutForSpec(doc.spec.id, doc.layout ?? null);
    setSpecFromDocument(doc);
    if (doc.session?.inputBytes) {
      setInputText(formatBytes(new Uint8Array(doc.session.inputBytes), fmt()));
    }
    if (doc.session?.keyBytes) {
      setKeyText(formatBytes(new Uint8Array(doc.session.keyBytes), fmt()));
    }
    setError(null);
    run();
  };

  /**
   * Inner Load pathway: parse the file's text content, then apply via
   * `applyDocument`. Factored out so the jsdom test can drive Load without
   * an actual File object.
   */
  const handleLoadFromText = (text: string): void => {
    const result = parseDocument(text);
    if (!result.ok) {
      setError(`Could not load this file: ${result.error}`);
      return;
    }
    applyDocument(result.doc);
  };

  /**
   * Click handler for the [Load…] button. Wraps the OS file picker in a
   * promise-y read; delegates the parsed text to `handleLoadFromText`.
   * jsdom-test pathway calls `handleLoadFromText` directly to sidestep
   * the file-picker dance.
   */
  const onLoadClick = (): void => {
    fileInputRef?.click();
  };
  const onFileChosen = (e: Event): void => {
    const target = e.currentTarget as HTMLInputElement;
    const file = target.files?.[0];
    if (!file) return;
    file
      .text()
      .then(handleLoadFromText)
      .catch((err) => {
        setError(`Could not load this file: ${err instanceof Error ? err.message : String(err)}`);
      })
      .finally(() => {
        // Reset the file input so re-picking the same file fires `change`.
        target.value = "";
      });
  };

  // Re-run when ANY input that feeds the cipher changes — spec edits
  // (S-box / param tweaks), plaintext/ciphertext, key, or IV. Only fires
  // when the user has opted into auto-rerun mode (the default). In manual
  // mode we instead flip the dirty flag so the UI can show an "edits
  // pending — click Run" banner, preserving the prior run snapshot for
  // comparison in the Run Explorer until the user deliberately commits
  // the batched edits.
  //
  // Tracking the input/key/IV signals (not just spec) means that typing in
  // the plaintext field or clicking "🎲 Randomize" on the IV produces the
  // same auto-rerun behavior as a spec edit. Before this, only spec edits
  // were watched, so the trace silently went stale on input/key/IV changes
  // and the "edits pending" banner never appeared either.
  //
  // Side effect: helpers like `changeFormat`/`changeCipher`/`changePadding`
  // and `applyDocument` call setInputText/setKeyText as a consequence of
  // selector changes, so each of those will now trigger an extra debounced
  // rerun on top of the spec-driven one. `pushSnapshot` dedups identical
  // configurations so history stays clean; the worst case is one wasted
  // sub-millisecond runtime call.
  //
  // The dep tuple is an array of *accessor functions* (not invoked values).
  // Solid's `on` accepts both forms; the array form means the body fires
  // when ANY of them change. `defer: true` keeps it from firing on initial
  // setup — neither mode should rerun before the user has hit Run once.
  createEffect(
    on(
      [spec, inputText, keyText, ivBytes],
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
  // Editor-surface selection. Drives both ParamEditor mounts (linear +
  // graph) so the editor binds to whichever step the user last touched,
  // regardless of whether that step has an executed trace frame backing
  // it. Kept in sync with the scrubber by `setFrame` + `setTrace` over in
  // `stores/trace.ts`, so linear-view scrubbing continues to update the
  // editor without any per-callsite plumbing here.
  const selectedStepId = useSelectedStepId();

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
        {/* When the live spec matches the canonical default for the current
            selectors, show the spec's own name ("AES-128", "AES-128 ECB",
            etc.). After any user edit (param tweak, palette insert, delete)
            switch to "Custom (was <variant>)" so the user can see at a glance
            that they've diverged. The variant comes from CIPHER_LABELS rather
            than spec.name on purpose — the indicator next to the dropdown
            uses the same source, keeping the two surfaces in sync. */}
        <span class="cipher-name" classList={{ "is-custom": isCustom() }}>
          {isCustom() ? `Custom (was ${CIPHER_LABELS[cipher()]})` : spec().name}
        </span>
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
          <div class="cipher-select-row">
            <select
              value={cipher()}
              onChange={(e) => changeCipher(e.currentTarget.value as Cipher)}
              title="AES variant — 128/192/256 differ in key length and round count"
            >
              {/* The selected option's label flips to "Custom (was AES-128)"
                  when the live spec has diverged from canonical. Picking the
                  same value from the dropdown is a no-op (no onChange) — the
                  reset button alongside is the action surface. We keep the
                  reset-to-canonical out of the dropdown to avoid hijacking
                  the cipher-switch semantics. */}
              <For each={CIPHER_OPTIONS}>
                {(c) => (
                  <option value={c}>
                    {c === cipher() && isCustom()
                      ? `Custom (was ${CIPHER_LABELS[c]})`
                      : CIPHER_LABELS[c]}
                  </option>
                )}
              </For>
            </select>
            {/* Visible only when the spec has diverged. Single reset surface
                — placed here next to the dropdown (the action surface) rather
                than mirrored next to the header indicator, so it doesn't
                compete with the muted cipher-name label. */}
            <Show when={isCustom()}>
              <button
                type="button"
                class="reset-spec-button"
                onClick={() => resetSpec()}
                title={`Discard edits and restore the canonical ${CIPHER_LABELS[cipher()]} spec`}
              >
                reset
              </button>
            </Show>
          </div>
        </label>
        <label>
          mode of operation
          <select
            value={cipherMode()}
            onChange={(e) => setCipherMode(e.currentTarget.value as CipherMode)}
            disabled={!isAesCipher(cipher())}
            title={
              isAesCipher(cipher())
                ? "Block-cipher mode of operation. 'single block' keeps the canonical FIPS-197 single-block trace. ECB encrypts each block independently (educational baseline — the Tux-image leak). CBC chains blocks via the IV + previous-ciphertext XOR so identical plaintext blocks produce different ciphertext. CTR ships in Phase 3. AES-128 is the only variant with the multi-block factories wired up today — AES-192/256 lands in Phase 4."
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
              disabled={
                !(SUPPORTED_CIPHER_MODES as readonly string[]).includes("cbc") ||
                !isCipherModeSupported(cipher(), "cbc")
              }
            >
              {CIPHER_MODE_LABELS.cbc}
              {isAesCipher(cipher()) && !isCipherModeSupported(cipher(), "cbc")
                ? " (AES-128 only in Phase 2)"
                : ""}
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
        {/* IV input: shown only when CBC is active. The all-zero default
            from the iv store is replaced by NIST §F's standard test
            vector so the first-impression CBC run against the §F sample
            plaintext matches the published §F.2.1 ciphertext. The
            randomize button uses crypto.getRandomValues. */}
        <Show when={cipherMode() === "cbc"}>
          <IvInput format={fmt()} />
        </Show>
        <button type="button" onClick={run}>
          run
        </button>
        <button type="button" onClick={resetSpec} title="Restore the canonical spec for this mode">
          reset spec
        </button>
        {/* Slice 5 — Save current document to a downloadable file. The
            checkbox below toggles between spec-only and full-session
            (selectors + inputs + key bytes). */}
        <button
          type="button"
          onClick={saveDocument}
          title="Download the current cipher as a .cipher.json file"
        >
          save…
        </button>
        {/* Hidden file picker; the visible button triggers it. We assign
            the ref so the button's onClick can call .click() — clicking
            a hidden file input via ref is the standard pattern when the
            file input itself can't carry the desired styling. */}
        <input
          type="file"
          accept=".json,.cipher.json,application/json"
          ref={(el) => {
            fileInputRef = el;
          }}
          style={{ display: "none" }}
          onChange={onFileChosen}
        />
        <button type="button" onClick={onLoadClick} title="Load a .cipher.json file">
          load…
        </button>
        {/* Slice 7 — Share. Encodes the current document (respecting the
            include-session toggle below) as a `#doc=…` URL and copies it
            to the clipboard. Inline status pings below the toolbar. */}
        <button
          type="button"
          onClick={() => {
            void shareDocument();
          }}
          title="Copy a shareable URL of the current cipher to the clipboard"
        >
          share…
        </button>
        <label
          class="include-session-toggle"
          title="Save inputs + key + selector state with the file (off by default — keeps spec-only files small and avoids leaking plaintext when sharing)"
        >
          <input
            type="checkbox"
            checked={includeSession()}
            onChange={(e) => setIncludeSession(e.currentTarget.checked)}
          />
          include session
        </label>
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
        {/* Slice 7 — Share feedback. Surfaces "Copied!" or a clipboard
            failure inline below the toolbar; auto-clears after 3s. */}
        <Show when={shareStatus()}>
          {(getStatus) => (
            <output
              class="share-status"
              classList={{
                "share-status-success": getStatus().kind === "success",
                "share-status-error": getStatus().kind === "error",
              }}
            >
              {getStatus().message}
            </output>
          )}
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

      {/* ─── Main trace view: tab bar + per-mode content ─────────────── */}
      <section class="trace-view">
        {/* Slice 2 — three mutually-exclusive views over the same spec/trace:
            linear (today's per-frame state + editor), graph (2D aux-flow),
            JSON (raw spec). The tab bar lives above the content so it's
            visible even before the first Run (graph & json work without a
            trace; linear shows its empty-state fallback). */}
        <div class="view-mode-tabs" role="tablist" aria-label="View mode">
          <For each={ALL_VIEW_MODES}>
            {(m) => (
              <button
                type="button"
                class="view-mode-tab"
                classList={{ active: viewMode() === m }}
                role="tab"
                aria-selected={viewMode() === m}
                onClick={() => setViewMode(m as ViewMode)}
              >
                {VIEW_MODE_LABELS[m]}
              </button>
            )}
          </For>
        </div>

        <Switch>
          <Match when={viewMode() === "linear"}>
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

                  {/* Editable params for the current step. Reads the
                      shared selection signal (kept in sync with the
                      scrubber by stores/trace.ts) rather than the frame
                      object — the editor must remain bound even when the
                      selected step has no trace frame (palette-dropped or
                      downstream of an upstream throw). */}
                  <ParamEditor stepId={selectedStepId()} />
                </>
              )}
            </Show>
          </Match>

          <Match when={viewMode() === "graph"}>
            <GraphView />
            {/* Slice 10 + trace-coupling-bug-fix follow-up: the graph
                view's editor pane reads the shared `selectedStepId`
                signal rather than the trace frame. Clicking a leaf in
                GraphView calls `setSelectedStepId` (which both binds the
                editor AND moves the scrubber if a frame matches), so the
                editor lights up even for steps that were just dropped
                from the palette and haven't been re-executed yet. The
                pane wrapper renders whenever there is a selection — on
                app boot the boot-run sets selectedStepId to the first
                frame's stepId, so the editor is visible immediately. */}
            <Show when={selectedStepId()}>
              {(graphStepId) => (
                <div class="graph-param-editor-pane">
                  <ParamEditor stepId={graphStepId()} />
                </div>
              )}
            </Show>
          </Match>

          <Match when={viewMode() === "json"}>
            {/* Raw spec JSON. Pretty-printed two-space; the surrounding
                <pre> preserves whitespace. Read-only for now; future slices
                can wire bidirectional edit + Zod parse here. */}
            <pre class="view-mode-json">{JSON.stringify(spec(), null, 2)}</pre>
          </Match>
        </Switch>
      </section>

      {/* ─── Sidebar: collapsible step tree ─────────────────────────── */}
      <aside class="step-list-pane">
        <h2>steps</h2>
        <StepList />
      </aside>

      {/* ─── Run Explorer modal (Phase 2c). Renders as a sibling so
            it can position fixed across the entire viewport. */}
      <RunExplorerModal isOpen={explorerOpen} onClose={() => setExplorerOpen(false)} />

      {/* ─── Footer ─────────────────────────────────────────────────
            Low-emphasis build stamp. The version surfaces which build
            the user is on (useful when reporting bugs or comparing a
            saved CipherDocument's `metadata.appVersion` to the live UI).
            See CHANGELOG.md and docs/versioning.md for the policy. */}
      <footer class="app-footer">
        <span class="muted small">Cryptographer v{APP_VERSION}</span>
        <a
          class="muted small"
          href="https://github.com/BoykoNeov/Cryptographer"
          target="_blank"
          rel="noopener noreferrer"
        >
          GitHub
        </a>
      </footer>
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

const SINGLE_STATE_BLOCK_BYTES = 16;

const SingleStateView = (props: { title: string; state: State }) => {
  const fmt = useByteFormat();

  // Derive cell descriptors per shape. Reading props.state inside the
  // memos keeps the views reactive to scrubber changes.
  const bytesCells = createMemo(() => {
    if (props.state.shape !== "bytes") return null;
    const bytes = props.state.bytes;
    return { length: bytes.length, indices: Array.from({ length: bytes.length }, (_, i) => i) };
  });

  // When the bytes sequence exceeds one block, slice the indices into
  // 16-cell groups so multi-block outputs (notably `concat-blocks`) render
  // as visually-separated blocks. This is what surfaces ECB's pedagogical
  // weakness — identical plaintext blocks → identical ciphertext blocks.
  const bytesBlockGroups = createMemo<number[][] | null>(() => {
    const c = bytesCells();
    if (!c) return null;
    if (c.length <= SINGLE_STATE_BLOCK_BYTES) return null;
    const out: number[][] = [];
    for (let i = 0; i < c.indices.length; i += SINGLE_STATE_BLOCK_BYTES) {
      out.push(c.indices.slice(i, i + SINGLE_STATE_BLOCK_BYTES));
    }
    return out;
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

  // Shared cell renderer for both the flat and grouped bytes branches.
  const renderByteCell = (i: number) => (
    <div class="bytes-cell">
      {/* Inline format read so a format toggle re-renders. */}
      {formatByte((props.state as BytesState).bytes[i] ?? 0, fmt())}
    </div>
  );

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
                <Show
                  when={bytesBlockGroups()}
                  fallback={<For each={getCells().indices}>{renderByteCell}</For>}
                >
                  {(getGroups) => (
                    <For each={getGroups()}>
                      {(group, gi) => (
                        <div class="bytes-block-group">
                          <div class="bytes-block-label">Block {gi() + 1}</div>
                          <div class="bytes-block-cells">
                            <For each={group}>{renderByteCell}</For>
                          </div>
                        </div>
                      )}
                    </For>
                  )}
                </Show>
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
 * Compact YYYYMMDD date string used in the default Save filename. UTC-day
 * is unnecessary here (the filename is for the user's own filesystem;
 * local-day is what they expect). Two-digit month/day padding so a saved
 * file from January (`01`) doesn't sort before December (`12`).
 */
const ymdToday = (): string => {
  const d = new Date();
  const y = d.getFullYear();
  const m = String(d.getMonth() + 1).padStart(2, "0");
  const day = String(d.getDate()).padStart(2, "0");
  return `${y}${m}${day}`;
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

/** Tiny shared formatter for catch blocks — keeps the call sites readable
 * and avoids the `e instanceof Error ? e.message : String(e)` chant
 * sprinkled across the file. */
const errMessage = (e: unknown): string => (e instanceof Error ? e.message : String(e));

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
