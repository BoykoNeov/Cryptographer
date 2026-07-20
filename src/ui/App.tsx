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

import { bytesToBigInt } from "@/core/big-int-codec";
import {
  CURRENT_SCHEMA_VERSION,
  type CipherDocument,
  parseDocument,
  serializeDocument,
} from "@/core/document";
import { type ByteFormat, formatBytes, parseBytes, parseBytesWithLength } from "@/core/format";
import { runSpec } from "@/core/runtime";
import { makeBytesState } from "@/core/state/bytes";
import type { AuxValue, State, TraceFrame } from "@/core/types";
import { APP_VERSION } from "@/version";
import {
  For,
  Match,
  Show,
  Switch,
  batch,
  createEffect,
  createMemo,
  createSignal,
  on,
  onCleanup,
  onMount,
} from "solid-js";
import { BlockBadge } from "./components/BlockBadge";
import { ConstantsPanel } from "./components/ConstantsPanel";
import { FeistelRecombineView } from "./components/FeistelRecombineView";
import { FeistelRoundBytes } from "./components/FeistelRoundBytes";
import { FeistelSwapDiagram } from "./components/FeistelSwapDiagram";
import { GraphView } from "./components/GraphView";
import { IvInput } from "./components/IvInput";
import { ParamEditor } from "./components/ParamEditor";
import { PortFlowView } from "./components/PortFlowView";
import { PortWiringEditor } from "./components/PortWiringEditor";
import { RoundKeyPanel } from "./components/RoundKeyPanel";
import { RunExplorerModal } from "./components/RunExplorerModal";
import { StepDescription } from "./components/StepDescription";
import { StepList } from "./components/StepList";
import { StepNarration } from "./components/StepNarration";
import { StepStrip } from "./components/StepStrip";
import { TraceTimeline } from "./components/TraceTimeline";
import { TwofishRoundDiagram } from "./components/TwofishRoundDiagram";
// Side-effect import: register the per-frame narration fns into the shared
// narration registry. Without it, <StepNarration /> would render nothing.
// Idempotent.
import "./narration/index";
import { clearDirty, setAutoRerun, setDirty, useAutoRerun, useDirty } from "./stores/auto-rerun";
import { blockByteLengthFor, hasBlockCipherCore } from "./stores/block-cipher-cores";
import {
  ASYMMETRIC_DESCRIPTIONS,
  ASYMMETRIC_LABELS,
  ASYMMETRIC_OPTIONS,
  type Algorithm,
  type Asymmetric,
  CIPHER_DESCRIPTIONS,
  CIPHER_LABELS,
  CIPHER_OPTIONS,
  type Category,
  type Cipher,
  DEFAULT_CT_BYTES_BY_CIPHER,
  DEFAULT_KEY_BYTES_BY_ASYMMETRIC,
  DEFAULT_KEY_BYTES_BY_CIPHER,
  DEFAULT_KEY_BYTES_BY_HASH,
  DEFAULT_PT_BYTES_BY_ASYMMETRIC,
  DEFAULT_PT_BYTES_BY_CIPHER,
  DEFAULT_PT_BYTES_BY_HASH,
  HASH_DESCRIPTIONS,
  HASH_LABELS,
  HASH_OPTIONS,
  type Hash,
  describeAlgorithm,
  historyOfAlgorithm,
  isAsymmetric,
  isCipher,
  isHash,
  useAlgorithm,
  useAsymmetric,
  useCategory,
  useCipher,
  useHash,
} from "./stores/cipher";
import {
  CIPHER_MODE_LABELS,
  type CipherMode,
  SUPPORTED_CIPHER_MODES,
  isCipherModeSupported,
  useCipherMode,
} from "./stores/cipher-mode";
import {
  installEditHistoryCapture,
  installEditHistoryShortcuts,
  redo,
  undo,
  useCanRedo,
  useCanUndo,
  withBoundaryReset,
} from "./stores/edit-history";
import { setByteFormat, useByteFormat } from "./stores/format";
import { pushSnapshot, useHistory } from "./stores/history";
import { DEFAULT_IV_LENGTH, reconcileIvWidth, useIvBytes } from "./stores/iv";
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
  MAX_KMAC_KEY_LENGTH,
  MAX_SHAKE_OUTPUT,
  isCustomSpec,
  isKmacHash,
  resetSpec,
  setAlgorithm,
  setAsymmetric,
  setCipher,
  setCipherMode,
  setCshakeCustomization,
  setHash,
  setKmacCustomization,
  setKmacKeyLength,
  setMode,
  setPadding,
  setShakeOutputLength,
  setSpecFromDocument,
  useCshakeN,
  useCshakeS,
  useKmacS,
  useMode,
  useShakeOutputLength,
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
// below one block (pkcs7 + iso7816-4 always append at least one byte), the
// FIPS vector would immediately fail the length check. Default to a short,
// visible word so the trace produces a clean pad/unpad frame on first Run.
// The bytes are the ASCII codepoints for "apple". Only reachable for a cipher
// with a core — a coreless one takes no padding, so its limits never cap short.
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
  // Slice 2.10c (2026-05-25) — algorithm-selector signals. `algorithm` is
  // the source of truth for runtime dispatch + the save-side `algorithm`
  // field; `category` flips the dropdown surface (cipher vs. hash); `hash`
  // is the active hash variant when `category === "hash"`. Two independent
  // signals (cipher + hash) preserve each family's last selection across a
  // cross-category detour — see [[feedback_remember_last_cipher]] / the
  // 2.10c plan's "Remember" user pick. Many of the conditional renders
  // below pivot on `isCipher(algorithm())` so the cipher-specific
  // controls (mode, cipher-mode, padding, key, IV) vanish when a hash is
  // active. Hash specs have no encrypt/decrypt direction, no block mode,
  // no padding overlay, and no key — gating each surface keeps the UI
  // from lying about what the spec actually consumes.
  const algorithm = useAlgorithm();
  const category = useCategory();
  const hash = useHash();
  const asymmetric = useAsymmetric();
  const shakeOutputLength = useShakeOutputLength();
  const cshakeN = useCshakeN();
  const cshakeS = useCshakeS();
  const kmacS = useKmacS();

  /** True when the active hash is a cSHAKE (editable N + S customization). */
  const isCshake = () => hash() === "cshake128" || hash() === "cshake256";
  /** True when the active hash is a KMAC variant (keyed; editable S; N fixed). */
  const isKmac = () =>
    hash() === "kmac128" ||
    hash() === "kmac256" ||
    hash() === "kmacxof128" ||
    hash() === "kmacxof256";
  /** True when the active hash is any XOF-length variant (SHAKE / cSHAKE / KMAC)
   *  — has an editable output length. */
  const isXof = () => hash() === "shake128" || hash() === "shake256" || isCshake() || isKmac();
  /** Sponge rate of the active XOF (bytes/squeeze-block) — for the block-count
   *  caption; 0 when not an XOF. 128-strength = 168, 256-strength = 136. */
  const shakeRate = () =>
    hash() === "shake128" ||
    hash() === "cshake128" ||
    hash() === "kmac128" ||
    hash() === "kmacxof128"
      ? 168
      : hash() === "shake256" ||
          hash() === "cshake256" ||
          hash() === "kmac256" ||
          hash() === "kmacxof256"
        ? 136
        : 0;
  /** True when the live spec consumes a key (byteLength > 0) — the honest test
   *  for showing the key field. Every cipher is keyed; hashes are keyless except
   *  KMAC (the first keyed hash); RSA/asymmetric declare byteLength 0. */
  const activeSpecConsumesKey = () => spec().inputs.key.byteLength > 0;

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
  //
  // Slice 2.10c (2026-05-25): hash category branches off the cipher-
  // specific resolution. Hashes have no padding overlay, no encrypt/
  // decrypt direction, and no key — the boot defaults come from the
  // dedicated `DEFAULT_*_BY_HASH` tables (key=empty, plaintext="abc"
  // per FIPS 180-4 §A.1). The branch fires only on a fresh load that
  // starts in hash category, which is not the default — but covers a
  // hypothetical future where the initial category persists or a test
  // boots with category="hash".
  //
  // RSA note: category boots "cipher" (session-only, never persisted — see
  // `stores/cipher.ts`), so the non-cipher branch here only ever runs for a
  // hash today. If the boot category ever becomes persistent, the asymmetric
  // case needs its own `DEFAULT_*_BY_ASYMMETRIC` arm; until then it would
  // harmlessly fall to the hash default (wrong bytes, no crash). The live
  // category swap is handled mode-aware by `changeCategory`.
  const initialPtBytes = isCipher(algorithm())
    ? (() => {
        const initialLimits = paddingLimits(mode(), padding(), cipher(), cipherMode());
        // An always-adds-a-byte scheme caps encrypt below a full block, so the
        // full-block default plaintext wouldn't fit — boot the short one instead.
        const blockBytes = blockByteLengthFor(cipher());
        return blockBytes !== undefined && mode() === "encrypt" && initialLimits.max < blockBytes
          ? DEFAULT_SHORT_PT_BYTES
          : DEFAULT_PT_BYTES_BY_CIPHER[cipher()];
      })()
    : DEFAULT_PT_BYTES_BY_HASH[hash()];
  const initialKeyBytes = isCipher(algorithm())
    ? DEFAULT_KEY_BYTES_BY_CIPHER[cipher()]
    : DEFAULT_KEY_BYTES_BY_HASH[hash()];
  const [inputText, setInputText] = createSignal(formatBytes(initialPtBytes, fmt()));
  const [keyText, setKeyText] = createSignal(formatBytes(initialKeyBytes, fmt()));
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

  // Wire the unified undo/redo capture observer (C2): one
  // `createEffect(on([specs, layout]))` that records a pre-change snapshot for
  // every spec edit or layout move. Made user-reachable in C4 via the toolbar
  // buttons below + the Ctrl+Z / Ctrl+Shift+Z / Ctrl+Y shortcuts.
  installEditHistoryCapture();

  // C4 — the undo/redo keyboard shortcuts. Separate handler from
  // `installKeyboardShortcuts` (which early-returns on `!trace`); this one
  // bails on editable targets so Ctrl+Z in an input does native text undo.
  installEditHistoryShortcuts();

  // C4 toolbar depth accessors (curried: call twice — `canUndo()` — to read the
  // reactive boolean; a single call is the accessor and always truthy).
  const canUndo = useCanUndo();
  const canRedo = useCanRedo();

  /**
   * Wrap a state-mutating `onInput` body so the page's vertical scroll
   * doesn't jump. Background: when an `<input>` is focused and the user
   * scrolls the page so the input is off-screen, then pastes (or in some
   * cases types) into it, browsers will scroll the focused input back
   * INTO VIEW so the caret stays visible. For the top-of-page key /
   * plaintext fields, that scroll yanks the user back to the top —
   * confirmed empirically on 2026-05-18 via a `scroll` event log
   * (`scrollY: 1843 → 145` in one event after a 32-char hex paste).
   *
   * S-box / matrix-cell inputs don't surface the same bug: the user
   * edits them while looking at them, so the scroll-into-view is a no-op.
   *
   * The fix saves `window.scrollY` before the value update and restores
   * it on the next animation frame — late enough that the browser's own
   * caret-into-view scroll has fired, early enough that the user doesn't
   * see a flash. Only restores when scrollY actually changed, so the
   * normal "type at top of page" case stays a no-op. Per-event scope:
   * no global listeners, no module state, no test surface to maintain.
   */
  const preserveScroll = (fn: () => void): void => {
    if (typeof window === "undefined") {
      fn();
      return;
    }
    const previousScrollY = window.scrollY;
    fn();
    window.requestAnimationFrame(() => {
      if (window.scrollY !== previousScrollY) {
        // Two-arg form is the synchronous one; ScrollToOptions with
        // `behavior: "instant"` would also work but isn't universally
        // typed in lib.dom.d.ts.
        window.scrollTo(window.scrollX, previousScrollY);
      }
    });
  };

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
      // Slice 2.10c (2026-05-25): cipher-specific length + alignment
      // validators are gated behind `isCipher(algorithm())`. `paddingLimits`
      // exhaustive-switches on `Cipher` (advisor flagged this as
      // load-bearing for the non-AES error messages — see the consult
      // notes recorded in commit body), so calling it with a hash value
      // would be a category error. The hash branch below produces its own
      // friendly length error.
      if (isCipher(algorithm())) {
        const { min, max } = paddingLimits(mode(), padding(), cipher(), cipherMode());
        if (inputBytes.length < min || inputBytes.length > max) {
          throw new Error(
            formatLengthError(
              mode(),
              padding(),
              cipher(),
              cipherMode(),
              inputBytes.length,
              min,
              max,
            ),
          );
        }
        // Multi-block ECB/CBC require block-aligned input on decrypt OR when
        // the padding scheme is "none" on encrypt. Catch it here with a
        // friendly error rather than letting the iterate's block split throw a
        // runtime-internals error from inside the loop.
        const needsAlignment =
          (cipherMode() === "ecb" || cipherMode() === "cbc" || cipherMode() === "ctr") &&
          (mode() === "decrypt" || padding() === "none");
        // A cipher in ECB/CBC always has a core, so the `?? 0` is unreachable;
        // it exists so a missing core can't turn into a `% NaN` that silently
        // passes every alignment check.
        const blockBytes = blockByteLengthFor(cipher()) ?? 0;
        if (needsAlignment && blockBytes > 0 && inputBytes.length % blockBytes !== 0) {
          throw new Error(
            `${inputLabel()}: must be a multiple of ${blockBytes} bytes (whole ${CIPHER_LABELS[cipher()]} blocks); got ${inputBytes.length}.`,
          );
        }
      } else if (isHash(algorithm())) {
        // Hash branch — today SHA-256 only. Slice 2.11b made the spec
        // multi-block (the per-block body folds over the padded N×64-byte
        // message, threading the running hash), so messages of any length
        // hash correctly. We still cap input — NOT for correctness but for
        // legibility: the decomposed trace is ~2299 frames PER 64-byte block,
        // so a multi-KB paste would build a multi-hundred-thousand-frame
        // trace and bog the linear scrubber. 512 bytes ≈ 9 blocks ≈ 21k
        // frames is a sane pedagogy ceiling (raise it if a use case needs
        // more). This is a tool-usability limit, not a SHA-256 limit.
        const MAX_HASH_INPUT = 512;
        if (inputBytes.length > MAX_HASH_INPUT) {
          throw new Error(
            `${inputLabel()}: ${HASH_LABELS[hash()]} accepts 0..${MAX_HASH_INPUT} bytes in this explorer; got ${inputBytes.length}. (SHA-256 itself has no such limit — the cap keeps the per-byte trace small enough to scrub. ${MAX_HASH_INPUT} bytes is ~${Math.ceil((MAX_HASH_INPUT + 9) / 64)} blocks.)`,
          );
        }
      } else {
        // Asymmetric (RSA) branch. The message m must satisfy 0 ≤ m < n,
        // else the square-and-multiply ladder silently computes (m mod n)ᵉ
        // and the round-trip won't recover m (green math, wrong behaviour).
        // Validate by VALUE against the live modulus n = p·q derived from the
        // spec's editable constants — NOT just the byte width.
        const consts = spec().cipherConstants;
        const p = consts?.p;
        const q = consts?.q;
        if (p !== undefined && q !== undefined) {
          const n = bytesToBigInt(p) * bytesToBigInt(q);
          const m = bytesToBigInt(inputBytes);
          if (m >= n) {
            throw new Error(
              `${inputLabel()}: value ${m} must be less than the modulus n = ${n} (= p·q). Textbook RSA only operates on integers in [0, n).`,
            );
          }
        }
      }

      // Key length depends on the active cipher: 16 (AES-128) / 24 (192) /
      // 32 (256). The spec carries this in inputs.key.byteLength — read it
      // off the live spec rather than threading the cipher signal in.
      //
      // KMAC is the exception: its key is VARIABLE-length (Option A — the key
      // field is the source of truth). Parse without a fixed-length check, then
      // make the spec's declared key length agree BEFORE running. Committing the
      // field on blur normally already did this, but a typed-then-Run edit that
      // never blurred would otherwise run a stale-length spec — and the runtime's
      // aux coercion would silently pad/truncate the key into a WRONG MAC.
      let keyBytes: Uint8Array;
      try {
        if (isKmac()) {
          const parsed = parseBytes(keyText(), fmt());
          if (parsed.length < 1) throw new Error("KMAC needs at least 1 key byte");
          if (parsed.length !== spec().inputs.key.byteLength) {
            setKmacKeyLength(parsed.length); // rebuilds spec() to the typed length
          }
          // If the declared length STILL disagrees after the resync, the key is
          // out of the [1, MAX] range that setKmacKeyLength clamps to — running
          // now would feed the full key into aux against a clamped (shorter)
          // declared length, and the runtime would silently coerce it into a
          // WRONG MAC. Reject at the boundary instead (MAX is the only remaining
          // divergence — the < 1 case already threw). The clamp is a legibility
          // cap on a derived-from-the-key quantity, so it must reject, not clip.
          if (parsed.length !== spec().inputs.key.byteLength) {
            throw new Error(`KMAC key too long: max ${MAX_KMAC_KEY_LENGTH} bytes`);
          }
          keyBytes = parsed;
        } else {
          keyBytes = parseBytesWithLength(keyText(), fmt(), spec().inputs.key.byteLength);
        }
      } catch (e) {
        throw new Error(`key: ${e instanceof Error ? e.message : String(e)}`);
      }

      // Initial state is always a BytesState — post-Slice-5.1 the only
      // State shape is `bytes` (every shipped cipher/hash is port-native
      // byte-flat; `inputs.plaintext.shape` is always `"bytes"`). The
      // runtime seeds the first byte-consumer from these bytes.
      const initialState: State = makeBytesState(inputBytes);

      const initialAux = new Map<string, AuxValue>([["key", keyBytes]]);
      // CBC seeds the IV from the dedicated `iv` store (the IvInput field
      // below). The store holds exactly one block of the ACTIVE cipher — not a
      // fixed 16: `setIvBytes` enforces the width its caller names, the
      // randomize button generates that width, and `reconcileIvWidth` re-defaults
      // the IV whenever a cipher/mode change moves the block size. So we can drop
      // straight into aux.
      // CTR reads the same aux slot, but the value plays a different role:
      // there it is the INITIAL COUNTER BLOCK that gets encrypted, not a value
      // XORed into the first block. One field, two meanings — the IV input's
      // label and the mode's narration carry the distinction.
      if (cipherMode() === "cbc" || cipherMode() === "ctr") {
        initialAux.set("iv", new Uint8Array(ivBytes()));
      }
      const currentSpec = spec();
      // Every spec is port-native (Phase C retired the legacy dispatch flag),
      // so the runtime always runs the single port-native path.
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
      // Algorithm selector hint (Phase 6e, widened from `cipher: Cipher`
      // to `algorithm: Algorithm` in Slice 2.10b of the universal-port
      // plan; reading from the `algorithm` signal in Slice 2.10c, 2026-
      // 05-25). Emitted on BOTH spec-only AND session-included paths so
      // a recipient's selector flips to match the loaded spec regardless
      // of the toggle. Deterministic — no Date.now() — so the spec-only
      // path stays byte-stable for URL-share hashing.
      algorithm: algorithm(),
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
    const includeIv = cipherMode() === "cbc" || cipherMode() === "ctr";
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
    // C3 stack boundary — a document Load is a canonical rebuild:
    // `applyDocumentInner` mints a fresh spec + layout map, and the restored
    // selectors no longer match any pre-load undo snapshot, so the accumulated
    // history is invalid. Suppress the transition writes and drop both stacks.
    // Wrapping HERE (rather than at each call site) is what covers the
    // `onMount` `#doc=` URL-share boot path too — advisor C3 note: the boot
    // load funnels through `applyDocument`, so it inherits the same boundary as
    // the manual [Load…] button without a separate onMount wrap.
    withBoundaryReset(() => applyDocumentInner(doc));
  };

  const applyDocumentInner = (doc: CipherDocument): void => {
    // Capture the recipient's algorithm BEFORE `setSpecFromDocument` flips
    // it, so the smart-swap below can compare the inputText/keyText
    // against the OLD algorithm's canonical defaults. Without this
    // capture, the swap check would compare against the new algorithm's
    // defaults and never swap. Slice 2.10c (2026-05-25) widened from
    // `prevCipher: Cipher` to `prevAlgorithm: Algorithm` so the smart-
    // swap branches symmetrically across cipher↔cipher (existing) and
    // cipher↔hash (new).
    const prevAlgorithm: Algorithm = algorithm();

    setLayoutForSpec(doc.spec.id, doc.layout ?? null);
    setSpecFromDocument(doc);
    if (doc.session?.inputBytes) {
      setInputText(formatBytes(new Uint8Array(doc.session.inputBytes), fmt()));
    }
    if (doc.session?.keyBytes) {
      setKeyText(formatBytes(new Uint8Array(doc.session.keyBytes), fmt()));
    }
    // Phase 6e of `docs/plans/des-feistel.md`: when the document carries
    // the optional algorithm hint AND does NOT carry saved bytes, mirror
    // the smart-swap policy from `changeCipher` so a recipient with a
    // fresh tab (current inputs are the OLD cipher's canonical defaults)
    // lands with inputs sized correctly for the NEW cipher. Without this
    // swap, a spec-only DES share loaded into an AES-128-default
    // recipient leaves a 16-byte plaintext in the field that immediately
    // errors "must be exactly 8 bytes." With it, the recipient sees the
    // DES FIPS 46-3 Appendix B vector and the FIPS ciphertext appears.
    //
    // The "match OLD defaults?" check is exactly the same heuristic
    // `changeCipher` uses for the manual cipher selector: user-typed
    // values are NEVER clobbered; only literal canonical-default carry-
    // over triggers the swap. So a load against a recipient who had
    // already typed their own plaintext keeps their work intact.
    //
    // Slice 2.10c (2026-05-25): smart-swap inputs against the previous
    // algorithm's canonical defaults if the doc carries a different
    // algorithm AND has no saved session bytes. Branches over both
    // cipher and hash sides — the helpers `algorithmDefaultKey` and
    // `algorithmDefaultPt` resolve to the right table per `isCipher` /
    // `isHash`. Without the swap, a non-AES doc landed into an AES-128
    // recipient leaves stale defaults that immediately error on Run
    // (DES needs 8-byte key, hash key field needs to be empty, etc.).
    //
    // Run order: this check fires AFTER setSpecFromDocument, so
    // `algorithm()` already reads the new value. We compare against
    // `prevAlgorithm` captured above the spec change.
    if (
      doc.algorithm !== undefined &&
      doc.algorithm !== prevAlgorithm &&
      !doc.session?.inputBytes &&
      !doc.session?.keyBytes
    ) {
      const currentKey = tryParseBytes(keyText(), fmt());
      const prevKeyDefault = algorithmDefaultKey(prevAlgorithm);
      if (currentKey && bytesEqual(currentKey, prevKeyDefault)) {
        const nextKey = algorithmDefaultKey(doc.algorithm);
        setKeyText(formatBytes(nextKey, fmt()));
        // A spec-only KMAC share carries no key bytes, so we drop in the 32-byte
        // canonical default; resync the store's variable-key-length mirror to it
        // (the loaded spec may have declared a different length). The store's
        // applyDocument set the mirror from the loaded spec; this overrides it to
        // match the default key we just placed in the field.
        if (isHash(doc.algorithm) && isKmacHash(doc.algorithm)) {
          setKmacKeyLength(nextKey.length);
        }
      }
      const currentPt = tryParseBytes(inputText(), fmt());
      const prevPtDefault = algorithmDefaultPt(prevAlgorithm);
      if (currentPt && bytesEqual(currentPt, prevPtDefault)) {
        setInputText(formatBytes(algorithmDefaultPt(doc.algorithm), fmt()));
      }
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
    // Input field: same policy, but the canonical default depends on the
    // active mode. In encrypt mode the field holds a PLAINTEXT; in decrypt
    // mode it holds a CIPHERTEXT (e.g. carried over by the mode-flip
    // auto-swap, which copies the previous mode's output in). Comparing
    // against the plaintext default in decrypt mode would never match a
    // ciphertext, so a stale block (e.g. AES's 16-byte CT) would survive a
    // switch to DES and trip the "must be exactly 8 bytes" banner — the bug
    // this branch fixes. Using the per-mode default table keeps the swap
    // working in both directions so the new cipher's first Run lands on its
    // canonical vector (decrypt round-trips straight back to the KAT
    // plaintext). A user-typed value (PT or CT) still never matches a
    // canonical default and is left untouched — the same sacred-input policy
    // as the key swap above; the user will see a friendly length error on
    // Run if it doesn't fit the new block size.
    const defaultForMode =
      mode() === "decrypt" ? DEFAULT_CT_BYTES_BY_CIPHER : DEFAULT_PT_BYTES_BY_CIPHER;
    const currentInput = tryParseBytes(inputText(), fmt());
    if (currentInput && bytesEqual(currentInput, defaultForMode[prev])) {
      setInputText(formatBytes(defaultForMode[next], fmt()));
    }
    // C3 stack boundary: a cipher switch rebuilds the spec off a selector that
    // isn't in the undo snapshot — suppress the rebuild, drop the history. (The
    // input/key smart-swaps above write only the text signals, which the
    // capture observer doesn't watch, so they stay outside the boundary.)
    withBoundaryReset(() => {
      setCipher(next);
      // The IV must be exactly one block wide, and the new cipher's block may
      // be a different size (AES 16 ↔ Blowfish 8). Inside the boundary because
      // `ivBytes` IS in the undo capture list.
      reconcileIvWidth(blockByteLengthFor(next));
    });
  };

  /**
   * Switch the active hash variant (Slice 2.10c, 2026-05-25). Same
   * smart-swap discipline as `changeCipher`: key + plaintext fields are
   * swapped IFF they currently hold the previous hash's canonical
   * default. Today's hash union has one member so this is forward-compat
   * for SHA-3 / SHA-512 landings; the function ships now so the hash
   * dropdown's onChange has a place to call.
   */
  const changeHash = (next: Hash): void => {
    const prev = hash();
    if (prev === next) return;
    const currentKey = tryParseBytes(keyText(), fmt());
    if (currentKey && bytesEqual(currentKey, DEFAULT_KEY_BYTES_BY_HASH[prev])) {
      const nextKey = DEFAULT_KEY_BYTES_BY_HASH[next];
      setKeyText(formatBytes(nextKey, fmt()));
      // KMAC's key length is variable and derived from the key field, so when we
      // swap in the canonical (32-byte) default we must resync the store's length
      // mirror — otherwise a persisted non-32 length would leave the rebuilt spec
      // declaring a length the key field no longer matches. (When the user kept a
      // custom key, its length is already committed, so no resync is needed.)
      if (isKmacHash(next)) setKmacKeyLength(nextKey.length);
    }
    const currentPt = tryParseBytes(inputText(), fmt());
    if (currentPt && bytesEqual(currentPt, DEFAULT_PT_BYTES_BY_HASH[prev])) {
      setInputText(formatBytes(DEFAULT_PT_BYTES_BY_HASH[next], fmt()));
    }
    // C3 stack boundary (see `changeCipher`): hash-variant switch rebuilds the
    // spec; suppress the rebuild and clear the now-stale undo history.
    withBoundaryReset(() => setHash(next));
  };

  /**
   * Change the SHAKE output length (the editable XOF digest length). Like a
   * hash-variant switch it rebuilds the spec structurally off a selector that
   * isn't in the undo snapshot — so it goes through the same C3 boundary reset:
   * suppress the rebuild's capture and clear the now-stale undo history. The
   * store clamps to [1, MAX_SHAKE_OUTPUT]; a no-op change (same length) still
   * costs only the clamp + a reference-equal setSpecs, so we don't guard it.
   */
  const changeShakeOutputLength = (next: number): void => {
    if (!Number.isFinite(next)) return; // ignore an empty / non-numeric field
    withBoundaryReset(() => setShakeOutputLength(next));
  };

  /**
   * Change a cSHAKE customization string (N or S). Like the output-length
   * control it is a STRUCTURAL rebuild off a selector outside the undo snapshot,
   * so it goes through the same C3 boundary reset.
   */
  const changeCshakeCustomization = (which: "N" | "S", value: string): void => {
    withBoundaryReset(() => setCshakeCustomization(which, value));
  };

  /** Change the KMAC customization string S (structural rebuild; same C3
   *  boundary reset as the cSHAKE / output-length controls). */
  const changeKmacCustomization = (value: string): void => {
    withBoundaryReset(() => setKmacCustomization(value));
  };

  /** Commit a new KMAC key length (structural rebuild; same C3 boundary reset as
   *  the other KMAC / XOF structural controls). */
  const changeKmacKeyLength = (len: number): void => {
    withBoundaryReset(() => setKmacKeyLength(len));
  };

  /**
   * On a KMAC key-field commit (blur / Enter), derive the key length from the
   * bytes the user typed and rebuild the spec at that length — KMAC's key length
   * is VARIABLE and the key field is its source of truth (Option A). A no-op for
   * every non-KMAC key field (those are fixed-length: the cipher declares the
   * size). Unparseable / empty text is left as-is for the Run handler to surface
   * as a parse error; we never rebuild at a guessed length. Skips the rebuild
   * when the length is unchanged (a pure value edit doesn't touch the structure).
   */
  const commitKmacKeyLength = (text: string): void => {
    if (!isKmac()) return;
    const bytes = tryParseBytes(text, fmt());
    if (!bytes || bytes.length < 1) return;
    if (bytes.length === spec().inputs.key.byteLength) return;
    changeKmacKeyLength(bytes.length);
  };

  /**
   * Flip the algorithm category (Slice 2.10c, 2026-05-25). Distinct from
   * `changeCipher` / `changeHash` because it crosses families — the smart-
   * swap compares the current key/plaintext against the OLD family's
   * canonical default (cipher OR hash, whichever was active) and replaces
   * with the NEW family's canonical (the value that `useAlgorithm()` will
   * resolve to AFTER the category flip). The two underlying signals
   * (cipher + hash) stay at their last-set values per the user-selected
   * "Remember" semantics, so flipping back returns to the same cipher.
   *
   * Routes through `setAlgorithm` in the spec store, which flips the
   * category signal AND rebuilds the spec with the canonical for the
   * destination family.
   */
  const changeCategory = (next: Category): void => {
    const prev = category();
    if (prev === next) return;
    const nextAlgorithm: Algorithm =
      next === "cipher" ? cipher() : next === "hash" ? hash() : asymmetric();
    const prevKeyDefault = algorithmDefaultKey(algorithm());
    const currentKey = tryParseBytes(keyText(), fmt());
    if (currentKey && bytesEqual(currentKey, prevKeyDefault)) {
      setKeyText(formatBytes(algorithmDefaultKey(nextAlgorithm), fmt()));
    }
    const prevPtDefault = algorithmDefaultPt(algorithm());
    const currentPt = tryParseBytes(inputText(), fmt());
    if (currentPt && bytesEqual(currentPt, prevPtDefault)) {
      setInputText(formatBytes(algorithmDefaultPt(nextAlgorithm), fmt()));
    }
    // C3 stack boundary (see `changeCipher`): crossing algorithm families
    // rebuilds the spec off the category signal; suppress + clear.
    withBoundaryReset(() => setAlgorithm(nextAlgorithm));
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
    // C3 stack boundary (see `changeCipher`): a padding-scheme switch rebuilds
    // the spec's padding overlay off a selector absent from the snapshot;
    // suppress + clear.
    withBoundaryReset(() => setPadding(next));
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
    if (s.shape !== "bytes") return null;
    return formatBytes(s.bytes, fmt());
  });

  // Run history feeds the Run Explorer modal. `historyCount` drives the
  // "compare runs (N)" button label and disables it when nothing has been
  // recorded yet. (The Phase-2b inline "compare to previous run" overlay
  // these once fed was retired with `BytesView` in Slice 5.3e — `PortFlowView`
  // has no previous-run row; cross-run diffing now lives only in the modal.)
  const history = useHistory();
  const historyCount = createMemo(() => history().length);

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
  // Slice 2.10c (2026-05-25): hash branch overrides the labels — hashes
  // are direction-less (no encrypt/decrypt; `mode()` is semantically
  // inert in the hash spec store), so input becomes "message" and output
  // becomes "digest". Without this override the UI would show
  // "plaintext (hex)" and "ciphertext (hex)" for a SHA-256 run, which is
  // a category lie.
  const inputLabel = () => {
    if (isHash(algorithm())) return "message";
    // RSA: encrypt consumes the message m, decrypt consumes the ciphertext c.
    if (isAsymmetric(algorithm())) return mode() === "encrypt" ? "message" : "ciphertext";
    return mode() === "encrypt" ? "plaintext" : "ciphertext";
  };
  const outputLabel = () => {
    if (isHash(algorithm())) return "digest";
    if (isAsymmetric(algorithm())) return mode() === "encrypt" ? "ciphertext" : "message";
    return mode() === "encrypt" ? "ciphertext" : "plaintext";
  };

  return (
    <div class="app">
      <header>
        <h1>Cryptographer</h1>
        {/* When the live spec matches the canonical default for the current
            selectors, show the spec's own name ("AES-128", "AES-128 ECB",
            "SHA-256", etc.). After any user edit (param tweak, palette
            insert, delete) switch to "Custom (was <variant>)" so the user
            can see at a glance that they've diverged. The variant comes
            from CIPHER_LABELS / HASH_LABELS rather than spec.name on
            purpose — the indicator next to the dropdown uses the same
            source, keeping the two surfaces in sync.

            Category branch (fixed 2026-05-26): originally this read
            `CIPHER_LABELS[cipher()]` unconditionally, which produced
            "Custom (was AES-128)" while the user was editing SHA-256 —
            cipher() still held its last-selected value while category
            was "hash". The S1 ParamEditor work made port-native
            primitives editable, so SHA-256 leaves CAN now diverge and
            this label was actively wrong. Branch on category(). */}
        <span class="cipher-name" classList={{ "is-custom": isCustom() }}>
          {isCustom()
            ? `Custom (was ${
                category() === "hash"
                  ? HASH_LABELS[hash()]
                  : category() === "asymmetric"
                    ? ASYMMETRIC_LABELS[asymmetric()]
                    : CIPHER_LABELS[cipher()]
              })`
            : spec().name}
        </span>
        {/* One-liner describing the active primitive, right after the cipher
            name next to "Cryptographer" (2026-07-11). Shown regardless of
            `isCustom()` — the description is about the ALGORITHM FAMILY, which
            doesn't change when the user diverges the spec, so blanking it on
            edit would drop useful context. Same text the selector caption
            shows, via the shared `describeAlgorithm` source of truth. */}
        <span class="cipher-desc muted small" title={describeAlgorithm(algorithm())}>
          {describeAlgorithm(algorithm())}
        </span>
        <span class="muted small kbd-hint">←/→ step · Home/End jump · PgUp/PgDn round</span>
      </header>

      {/* ─── Inputs row ─────────────────────────────────────────────── */}
      <section class="inputs">
        {/* Slice 2.10c (2026-05-25) — category selector. Sits at the
            front of the inputs row so the user reads "what KIND of
            primitive am I working with?" first; the specific dropdown
            below (cipher OR hash) is conditional on this choice. Two
            options today (Cipher | Hash); SHA-3 / MAC / KDF / RSA
            families would extend the Category union without rearranging
            the surface. The previous Cipher / Hash selections are
            preserved per the "Remember last cipher" semantic so a
            cipher → hash → cipher detour returns the user to the same
            cipher they were on. */}
        <label>
          kind
          <select
            value={category()}
            onChange={(e) => changeCategory(e.currentTarget.value as Category)}
            title="Cipher = symmetric encrypt/decrypt with a key. Hash = one-way digest (no key, no direction). Public-key = asymmetric (RSA) — encrypt/decrypt with a key pair, no symmetric key field."
          >
            <option value="cipher">Cipher</option>
            <option value="hash">Hash</option>
            <option value="asymmetric">Public-key</option>
          </select>
        </label>
        {/* Slice 2.10c — mode selector hidden for hash category. Hashes
            have no encrypt/decrypt direction; showing the toggle would
            be a category lie. The spec store carries a dead `mode`
            signal in hash mode (the discriminated `HashSpecsByMode`
            ignores `mode()`); hiding the selector here is the UI half
            of that contract. */}
        <Show when={!isHash(algorithm())}>
          <label>
            mode
            <select
              value={mode()}
              onChange={(e) => {
                // UX-H 2026-05-23 — When flipping mode, copy the
                // just-computed output into the input field so the user
                // doesn't see decrypt re-run on the stale plaintext
                // (computing it AS ciphertext) and produce a nonsense
                // result until they manually paste the previous output.
                // Symmetric: encrypt→decrypt copies the ciphertext in;
                // decrypt→encrypt copies the recovered plaintext in.
                // The IV is intentionally left alone per the plan note —
                // CBC-IV is a separate axis the user may want to keep or
                // edit independently of the mode flip.
                //
                // Captured BEFORE the mode change so we get the previous
                // mode's output (the value the user actually sees in the
                // result row right now), not whatever the new mode's
                // re-run produces. `batch` ensures the spec rebuild for
                // the new mode and the input swap land in one Solid
                // update cycle, avoiding a flicker where decrypt
                // momentarily runs on the encrypt-mode input.
                const newMode = e.currentTarget.value as "encrypt" | "decrypt";
                const swapText = outputText();
                batch(() => {
                  setMode(newMode);
                  if (swapText) setInputText(swapText);
                });
              }}
            >
              <option value="encrypt">encrypt</option>
              <option value="decrypt">decrypt</option>
            </select>
          </label>
        </Show>
        {/* Slice 2.10c — cipher dropdown shown only when category=cipher.
            Hash category swaps in the parallel hash dropdown below. */}
        <Show when={category() === "cipher"}>
          {/* `position: relative` so the divergence-only reset button can be
              absolutely positioned in the label's top-right dead space (next
              to the ~40px "cipher" caption). Keeping it OUT of the flex flow is
              deliberate: the button used to live inside `.cipher-select-row`,
              and its appearance on first divergence widened the cipher item
              ~52px, tipping a settings sibling onto a new line and growing
              `.inputs` ~54px (once per session, anchoring-masked at wide
              viewports, visible at narrow ones). Absolute positioning inside
              the caption's reliable dead space means the button's appearance
              reflows nothing. (Residual, out of scope: for Speck/Serpent-256
              the `<select>` itself grows on divergence because
              "Custom (was Speck 32/64 (BE, paper))" exceeds the widest normal
              option that otherwise pins the select width — the reported case is
              the AES-128 landing, where "Custom (was AES-128)" is narrower than
              that pin, so the select stays put and the button was the sole
              contributor.) */}
          <label class="cipher-label">
            cipher
            <div class="cipher-select-row">
              <select
                value={cipher()}
                onChange={(e) => changeCipher(e.currentTarget.value as Cipher)}
                // Tooltip reflects the CURRENT selection's one-liner (2026-07-11)
                // so hovering the closed dropdown surfaces "what is this cipher";
                // each <option> carries its own via `title` below so the user can
                // compare while the list is open. The always-visible copy lives
                // in the header caption.
                title={CIPHER_DESCRIPTIONS[cipher()]}
              >
                {/* The selected option's label flips to "Custom (was AES-128)"
                  when the live spec has diverged from canonical. Picking the
                  same value from the dropdown is a no-op (no onChange) — the
                  reset button alongside is the action surface. We keep the
                  reset-to-canonical out of the dropdown to avoid hijacking
                  the cipher-switch semantics. */}
                <For each={CIPHER_OPTIONS}>
                  {(c) => (
                    <option value={c} title={CIPHER_DESCRIPTIONS[c]}>
                      {c === cipher() && isCustom()
                        ? `Custom (was ${CIPHER_LABELS[c]})`
                        : CIPHER_LABELS[c]}
                    </option>
                  )}
                </For>
              </select>
            </div>
            {/* Visible only when the spec has diverged. Single reset surface
              — placed on the cipher control (the action surface) rather than
              mirrored next to the header indicator, so it doesn't compete with
              the muted cipher-name label. Absolutely positioned (see the
              `.cipher-label` `position: relative` note above) so its appearance
              never reflows the `.inputs` settings row. */}
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
          </label>
        </Show>
        {/* Slice 2.10c (2026-05-25) — hash dropdown shown only when
            category=hash. Today's HASH_OPTIONS has a single entry
            (SHA-256); the same `<For>` shape scales when SHA-3 /
            SHA-512 / SHAKE variants land. The cipher dropdown's reset-
            to-canonical button isn't mirrored here yet — Slice S1 of
            sha-256-density-polish (2026-05-26) added ParamEditor blocks
            for port-native primitives, so SHA-256 leaves CAN now diverge
            and the `Custom (was SHA-256)` indicator DOES fire (the
            header label was fixed in the same session to branch on
            category()). Add the reset button alongside when reset-to-
            canonical for hashes is wired up. */}
        <Show when={category() === "hash"}>
          <label>
            hash
            <select
              value={hash()}
              onChange={(e) => changeHash(e.currentTarget.value as Hash)}
              title={HASH_DESCRIPTIONS[hash()]}
            >
              <For each={HASH_OPTIONS}>
                {(h) => (
                  <option value={h} title={HASH_DESCRIPTIONS[h]}>
                    {HASH_LABELS[h]}
                  </option>
                )}
              </For>
            </select>
          </label>
          {/* SHAKE is a variable-length XOF: expose an editable output length so
              the user can watch squeeze blocks appear / disappear. Structural
              rebuild on commit (onChange = blur/Enter/spinner, NOT per-keystroke
              — a rebuild is ~hundreds of leaves). Bounded by MAX_SHAKE_OUTPUT
              for trace legibility; the block-count caption makes the squeeze
              loop's growth explicit. */}
          <Show when={isXof()}>
            <label class="shake-output-length" title="XOF output length in bytes">
              output bytes
              <input
                type="number"
                min={1}
                max={MAX_SHAKE_OUTPUT}
                step={1}
                value={shakeOutputLength()}
                onChange={(e) => changeShakeOutputLength(e.currentTarget.valueAsNumber)}
              />
            </label>
            <span class="shake-block-caption">
              {(() => {
                const rate = shakeRate();
                const blocks = rate > 0 ? Math.ceil(shakeOutputLength() / rate) : 0;
                return `${blocks} squeeze block${blocks === 1 ? "" : "s"} · rate ${rate} · max ${MAX_SHAKE_OUTPUT}`;
              })()}
            </span>
          </Show>
          {/* cSHAKE customization strings (SP 800-185): N (function name,
              reserved — empty for direct use) and S (user customization).
              Editing either is a STRUCTURAL rebuild (their length changes the
              encode_string / bytepad prefix), so commit on change, not per
              keystroke. Emptying BOTH flips the domain byte back to SHAKE's
              0x1F — the spec then renders as a plain SHAKE pipeline. */}
          <Show when={isCshake()}>
            <label
              class="cshake-custom"
              title="cSHAKE function name N (reserved; empty for direct use)"
            >
              N (name)
              <input
                type="text"
                value={cshakeN()}
                placeholder="(empty)"
                onChange={(e) => changeCshakeCustomization("N", e.currentTarget.value)}
              />
            </label>
            <label
              class="cshake-custom"
              title="cSHAKE customization string S — domain-separates the XOF"
            >
              S (custom)
              <input
                type="text"
                value={cshakeS()}
                placeholder="(empty)"
                onChange={(e) => changeCshakeCustomization("S", e.currentTarget.value)}
              />
            </label>
            <Show when={cshakeN() === "" && cshakeS() === ""}>
              <span class="shake-block-caption">
                empty N &amp; S ⇒ reduces to SHAKE (domain 0x1F)
              </span>
            </Show>
          </Show>
          {/* KMAC customization: only S is the user's — the function name N is
              the fixed ASCII "KMAC" (shown read-only). The key is entered in the
              key field above (KMAC is the first keyed hash). Editing S is a
              structural rebuild, like cSHAKE. */}
          <Show when={isKmac()}>
            <span class="cshake-custom cshake-fixed" title="KMAC's function name N is fixed">
              N = "KMAC"
            </span>
            <label
              class="cshake-custom"
              title="KMAC customization string S — optional domain separation"
            >
              S (custom)
              <input
                type="text"
                value={kmacS()}
                placeholder="(empty)"
                onChange={(e) => changeKmacCustomization(e.currentTarget.value)}
              />
            </label>
          </Show>
        </Show>
        {/* Public-key (asymmetric) dropdown — shown only when
            category=asymmetric. RSA today. Mirrors the cipher dropdown's
            reset-to-canonical affordance: the editable p/q/e constants mean
            the spec CAN diverge, so the "Custom (was RSA …)" indicator + reset
            button apply here too. One option today; the `<For>` shape scales. */}
        <Show when={category() === "asymmetric"}>
          <label class="cipher-label">
            algorithm
            <div class="cipher-select-row">
              <select
                value={asymmetric()}
                onChange={(e) =>
                  // C3 stack boundary (see `changeCipher`): an asymmetric-
                  // variant switch rebuilds the spec; suppress + clear.
                  withBoundaryReset(() => setAsymmetric(e.currentTarget.value as Asymmetric))
                }
                title={ASYMMETRIC_DESCRIPTIONS[asymmetric()]}
              >
                <For each={ASYMMETRIC_OPTIONS}>
                  {(a) => (
                    <option value={a} title={ASYMMETRIC_DESCRIPTIONS[a]}>
                      {a === asymmetric() && isCustom()
                        ? `Custom (was ${ASYMMETRIC_LABELS[a]})`
                        : ASYMMETRIC_LABELS[a]}
                    </option>
                  )}
                </For>
              </select>
            </div>
            <Show when={isCustom()}>
              <button
                type="button"
                class="reset-spec-button"
                onClick={() => resetSpec()}
                title={`Discard edits and restore the canonical ${ASYMMETRIC_LABELS[asymmetric()]} spec`}
              >
                reset
              </button>
            </Show>
          </label>
        </Show>
        {/* Slice 2.10c (2026-05-25) — cipher-specific selectors. Mode of
            operation + padding both apply only to block ciphers; for
            hash specs they have no semantic role. Hiding (not just
            disabling) is the UI half of the spec store's discriminated
            union contract — `HashSpecsByMode` carries no cipherMode /
            padding axes. The two `<label>`s are siblings inside the
            same `<Show>` because their visibility condition is identical
            (`isCipher(algorithm())`), so a single gate keeps the JSX
            compact. */}
        <Show when={isCipher(algorithm())}>
          <label>
            mode of operation
            <select
              value={cipherMode()}
              onChange={(e) =>
                // C3 stack boundary (see `changeCipher`): a mode-of-operation
                // switch rebuilds the spec (single-block ↔ ECB/CBC); suppress
                // + clear.
                withBoundaryReset(() => {
                  setCipherMode(e.currentTarget.value as CipherMode);
                  // The OTHER moment a stale IV goes live, and the one a
                  // cipher-change-only fix misses: land on Blowfish in
                  // single-block (where the IV is inert), then flip to CBC —
                  // no cipher change fires, but the IV is suddenly load-bearing.
                  reconcileIvWidth(blockByteLengthFor(cipher()));
                })
              }
              disabled={!hasBlockCipherCore(cipher())}
              title={
                hasBlockCipherCore(cipher())
                  ? "Block-cipher mode of operation. 'single block' keeps the canonical FIPS-197 single-block trace. ECB encrypts each block independently (educational baseline — the Tux-image leak). CBC chains blocks via the IV + previous-ciphertext XOR so identical plaintext blocks produce different ciphertext. CTR is designed for but not built."
                  : `Modes of operation need a cipher whose body can read its block from the loop — ${CIPHER_LABELS[cipher()]} runs as a single-block cipher in this build.`
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
                {hasBlockCipherCore(cipher()) && !isCipherModeSupported(cipher(), "ecb")
                  ? " (not wired up for this cipher yet)"
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
                {hasBlockCipherCore(cipher()) && !isCipherModeSupported(cipher(), "cbc")
                  ? " (not wired up for this cipher yet)"
                  : ""}
              </option>
              <option
                value="ctr"
                disabled={
                  !(SUPPORTED_CIPHER_MODES as readonly string[]).includes("ctr") ||
                  !isCipherModeSupported(cipher(), "ctr")
                }
              >
                {CIPHER_MODE_LABELS.ctr}
                {hasBlockCipherCore(cipher()) && !isCipherModeSupported(cipher(), "ctr")
                  ? " (not wired up for this cipher yet)"
                  : ""}
              </option>
            </select>
          </label>
          <label>
            padding
            <select
              value={padding()}
              onChange={(e) => changePadding(e.currentTarget.value as PaddingScheme)}
              disabled={!hasBlockCipherCore(cipher())}
              title={
                hasBlockCipherCore(cipher())
                  ? "Padding scheme applied at the start of encrypt / end of decrypt"
                  : `Padding needs a cipher the overlay can wire itself into — ${CIPHER_LABELS[cipher()]} takes exactly one block of input in this build.`
              }
            >
              <For each={PADDING_SCHEME_OPTIONS}>
                {(scheme) => <option value={scheme}>{PADDING_SCHEME_LABELS[scheme]}</option>}
              </For>
            </select>
          </label>
        </Show>
        {/* Always-visible HISTORICAL one-liner for the active primitive, on its
            own full-width row directly below the selector controls. Deliberately
            a DIFFERENT flavour from the header caption (2026-07-12): the header
            keeps the structural `describeAlgorithm` line, this tells the story
            (designer, year, lineage) via `historyOfAlgorithm` so the two
            surfaces complement rather than duplicate. Full-width (`flex: 0 0
            100%`, like `.inputs-result` / the pending banner) so it wraps to its
            own line rather than squeezing into the settings row and reflowing it. */}
        <p class="selector-caption muted small" title={historyOfAlgorithm(algorithm())}>
          {historyOfAlgorithm(algorithm())}
        </p>
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
        {/* UX-I 2026-05-23 — Data fields (input/key/IV/result) carry
            the `data-field` class so CSS can force each onto its own
            full-width row inside the wrapping flex container. The
            settings dropdowns above (mode/cipher/mode-of-op/padding/
            bytes) keep the old wrap-row behavior and continue to share
            row(s) at the top; the data fields stack vertically below;
            the action buttons wrap into the row(s) below that. Visual
            sequence becomes "what-I-edit → key → IV(opt) → result",
            each on its own line — matches the user's mental model of
            "thing-I-edit, key, what-came-out." */}
        <label class="data-field">
          {inputLabel()} ({fmt()})
          <input
            value={inputText()}
            onInput={(e) => preserveScroll(() => setInputText(e.currentTarget.value))}
            spellcheck={false}
          />
        </label>
        {/* Key field shown whenever the live spec CONSUMES a key
            (`inputs.key.byteLength > 0`) — the honest test. Every cipher is
            keyed; most hashes are keyless (SHA-256 declares byteLength 0, so a
            key label would just invite dead typing) — but KMAC (SP 800-185) is
            the first KEYED hash, so the field lights up for it. RSA/asymmetric
            declare byteLength 0 and stay hidden. */}
        <Show when={activeSpecConsumesKey()}>
          <label class="data-field">
            key ({fmt()})
            <input
              value={keyText()}
              onInput={(e) => preserveScroll(() => setKeyText(e.currentTarget.value))}
              // KMAC key length is VARIABLE and DERIVED from this field (Option
              // A): committing the field (blur / Enter) rebuilds the spec at the
              // typed length. No-op for every fixed-length cipher key.
              onChange={(e) => commitKmacKeyLength(e.currentTarget.value)}
              spellcheck={false}
            />
          </label>
          {/* KMAC's key is variable-length (SP 800-185 places no bound; we cap at
              MAX for trace legibility). Surface the live length so the "type any
              length" affordance is discoverable — the field itself is the only
              control. */}
          <Show when={isKmac()}>
            <span class="shake-block-caption">
              key = {spec().inputs.key.byteLength} bytes · variable (type any length, 1–
              {MAX_KMAC_KEY_LENGTH})
            </span>
          </Show>
        </Show>
        {/* IV input: shown only when CBC is active. The all-zero default
            from the iv store is replaced by NIST §F's standard test
            vector so the first-impression CBC run against the §F sample
            plaintext matches the published §F.2.1 ciphertext. The
            randomize button uses crypto.getRandomValues. Wrapped in a
            `data-field` div so the IvInput's own `<label>` root doesn't
            need a class hook — the wrapper carries the full-row layout. */}
        <Show when={cipherMode() === "cbc" || cipherMode() === "ctr"}>
          <div class="data-field">
            <IvInput
              format={fmt()}
              blockByteLength={blockByteLengthFor(cipher()) ?? DEFAULT_IV_LENGTH}
            />
          </div>
        </Show>
        {/* Result line sits adjacent to plaintext/key in the inputs row
            (was previously below the button strip — Phase 6e smoke
            finding 2026-05-20: a single visual neighbourhood of "what
            went in, what came out" reads faster than scanning past the
            action buttons to find the ciphertext). The label flips to
            "plaintext" in decrypt mode (`outputLabel()` derives from
            `mode()`), so the result row mirrors whichever input is
            currently the cipher's output. */}
        {/* UX-J 2026-05-23 — Result renders as label-above-code (a
            flex column), mirroring the input + key fields' `<label>`
            stack. Previously the row read inline as
            "ciphertext (hex): <code>...</code>", which made the result
            visually look like a different KIND of thing (caption-with-
            value) from the input fields next to it (label-above-input).
            Now the trio of (input, key, result) shares one visual
            grammar, reinforcing that the result is the third member of
            the same data row — just on the output side. */}
        <Show when={!error() && outputText()}>
          <div class="result inputs-result data-field">
            <span class="result-label">
              {outputLabel()} ({fmt()})
            </span>
            <code>{outputText()}</code>
          </div>
        </Show>
        <button type="button" onClick={run}>
          run
        </button>
        {/* C4 (graph-legibility plan) — unified undo/redo across BOTH spec edits
            and layout moves. Document-level placement (beside run/save), since a
            single undo can span spec + layout + document state. Disabled via the
            reactive depth accessors; the same actions bind to Ctrl+Z / Ctrl+Shift+Z. */}
        <button
          type="button"
          onClick={undo}
          disabled={!canUndo()}
          title="Undo the last edit (Ctrl+Z)"
        >
          undo
        </button>
        <button
          type="button"
          onClick={redo}
          disabled={!canRedo()}
          title="Redo the last undone edit (Ctrl+Shift+Z)"
        >
          redo
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
            button — visually adjacent to the action that clears it.

            Why the always-present SLOT (gated on manual mode, not on
            `dirty`): the banner appears/disappears on every edit→Run cycle
            — exactly the batch workflow manual mode exists for. Toggling a
            full-width row in/out of `.inputs` grew the section ~41px and
            shoved the whole page down (scroll anchoring masks it only when
            there's scroll headroom above the viewport; a tall viewport /
            near-top edit shows a visible jump — measured +176px). Reserving
            the row whenever auto-rerun is off, and only swapping its CONTENT
            on `dirty`, keeps `.inputs` height constant across the cycle so
            nothing jumps. The two states share box metrics (see app.css) so
            the row height is identical whether dirty or idle. */}
        <Show when={!autoRerun()}>
          <div class="pending-banner-slot">
            <Show
              when={dirty()}
              fallback={
                // Idle filler: keeps the slot at the banner's height (a bare
                // empty gap reads as a rendering bug) and quietly reminds the
                // user that edits won't apply until they Run. Plain <span> so
                // it carries no status role — only the live banner announces.
                <span class="pending-banner-idle">auto-rerun off — edits apply on run</span>
              }
            >
              {/* Native <output> carries an implicit `role="status"` so screen
                  readers announce the change without us repeating the role. */}
              <output class="pending-banner">
                edits pending — click <strong>run</strong> to update the trace
              </output>
            </Show>
          </div>
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

      {/* ─── Errors (result moved into the inputs row, 2026-05-20) ──── */}
      <Show when={error()}>
        <div class="error">{error()}</div>
      </Show>

      {/* ─── Trace timeline scrubber ─────────────────────────────────────
          Hidden in graph view: graph-mode users drive the inspector by
          clicking nodes/edges, not by scrubbing frame indices, so the
          slider was carrying no role there. User-flagged 2026-05-20
          Phase 6e smoke. JSON view also has no use for the slider but
          historically kept it; preserving that for now and only gating
          graph mode. */}
      <Show when={viewMode() !== "graph"}>
        <TraceTimeline />
      </Show>

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
                      <span class="frame-type">{frame().stepType}</span>
                    </div>
                  </div>

                  {/* Neighborhood strip: prev / current / next thumbnails. */}
                  <StepStrip />

                  {/* Multi-block context chip. Only renders when the current
                      frame belongs to an iterate node (blockIndex is set). */}
                  <BlockBadge blockIndex={frame().blockIndex} blockCount={blockCount()} />

                  {/* State view (PortFlowView for every shipped frame; see
                      `FrameStateView`). Every key schedule is now decomposed
                      into port-native primitive frames (K1–K4), so each stage
                      is a real, scrubbable frame the standard view renders
                      directly — the old `<KeyScheduleExplorer />` intercept
                      (which faked that decomposition for the monolithic
                      executors) was retired in K4b once DES, the last
                      monolithic schedule, decomposed. */}
                  <FrameStateView frame={frame()} />

                  {/* Port-native Feistel/swap visualization (Slice 5.3d — the
                      obligatory rebuild). These self-detect a port-native
                      Feistel round structurally from the round group's wiring
                      (no `branchPath`, no `feistel-round` kind) and render
                      nothing otherwise, so they're inert for every non-Feistel
                      cipher. The diagram + bytes panel pair whenever the active
                      frame is inside a Feistel round; the recombine inspector
                      adds itself on the `concat` frame. (The old `branchPath`/
                      `__rejoin__` toy components were retired in Slice 5.3e.) */}
                  <div class="feistel-port-pair">
                    <FeistelRoundBytes frame={frame()} />
                    <FeistelSwapDiagram frame={frame()} />
                  </div>
                  <FeistelRecombineView frame={frame()} />

                  {/* Twofish's round is 4-rail, not the 2-way Feistel form, so
                      every component above returns null for it (their shared
                      `analyzeFeistelRound` rejects the 4-input recombine). This
                      is the Twofish learner's equivalent: the abstract round +
                      the 4-way swap the per-step chain hides. Self-detecting
                      from the round's wiring, so it's inert everywhere else. */}
                  <TwofishRoundDiagram frame={frame()} />

                  {/* Per-frame value-prose. Cipher-agnostic dispatch via
                      the narration registry (`src/ui/narration/`).
                      Renders nothing for frames whose step type is on
                      the allowlist (the monolithic key-expansion oracle
                      executors are — they're aux-only no-ops not emitted by
                      any shipped spec, kept only for KAT/back-compat).
                      For AES round-body frames the registry returns one
                      <details> per conceptual sub-unit — 16 byte units
                      for SubBytes / AddRoundKey, 4 row units for
                      ShiftRows, 4 column units for MixColumns. */}
                  <StepNarration frame={frame()} />

                  {/* Round-key schedule panel. Cipher-agnostic: scans
                      `trace.finalAux` for `prefix.N` Uint8Array sequences
                      (AES's `roundKey.0..Nr`, Serpent's `roundKey.0..32`,
                      Speck's 2-byte subkeys) and renders each as a ribbon.
                      Highlights the K_i the current frame is reading via
                      auxRead. Hidden when no sequences exist (very-early
                      boot, or a hypothetical no-schedule cipher).
                      Positioned BELOW the FrameStateView (and ABOVE
                      StepDescription) so the ribbon visually couples with
                      the matrices it relates to during AddRoundKey hover,
                      rather than being separated by the larger
                      StepDescription block. Collapsible — defaults to
                      expanded on key-expansion / AddRoundKey frames,
                      collapsed otherwise; clicking the header overrides
                      until the next spec change. */}
                  <RoundKeyPanel frame={frame()} />

                  {/* Human-readable explanation of what this step does. */}
                  <StepDescription frame={frame()} />

                  {/* Editable published cipher constants (SHA-256's K/H;
                      AES S-box later). Renders nothing for specs without
                      `cipherConstants`. Sits above the per-step ParamEditor
                      so "constants" and "params" read as a pair. */}
                  <ConstantsPanel />

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
            {/* Cipher-constants panel — shown in graph view too (the
                linear-mode step tree is hidden here, so this is the only
                constants surface while wiring ports). Independent of any
                node selection, so it sits outside the selection-gated
                editor pane below. */}
            <ConstantsPanel />
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
                  {/* Port-wiring editor (4d-bis): rewire the selected leaf's
                      input ports to any scope-legal upstream source. Graph-mode
                      authoring only — sits below the param editor in the same
                      selection-gated pane. */}
                  <PortWiringEditor stepId={graphStepId()} />
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

      {/* ─── Sidebar: collapsible step tree ───────────────────────────
          Hidden in graph view by user request — graph users click nodes
          directly, so the linear-mode StepList navigation isn't doing
          work there. Preserved in linear + JSON views. (Phase 6e smoke
          2026-05-20.) */}
      <Show when={viewMode() !== "graph"}>
        <aside class="step-list-pane">
          <h2>steps</h2>
          <StepList />
        </aside>
      </Show>

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
 * Renders one frame's port I/O. `PortFlowView` is the UNIVERSAL inspector:
 * every shipped cipher/hash is port-native (every leaf's registration has
 * `legacy === undefined`, the port-capture gate at ~`runtime.ts:767`), so the
 * runtime records each frame's input/output ports and this view reads them
 * directly. The hybrid-ported family (the monolithic key-expansion oracle
 * executors + padding, `meta` retained) populates the same port fields. The
 * oracle key-expansion frames are no longer emitted by any shipped spec (every
 * schedule decomposed into port-native primitives in K1–K4), so in practice
 * padding is the hybrid family that lands in this view.
 *
 * The legacy shape-aware before/after dispatch was retired across Phase 5:
 * the matrix branch (`MatrixView`/`MixedShapeView`) with the `MatrixState`
 * shape in Slice 5.1, and the `BytesView` before/after pair itself in Slice
 * 5.3e once the last lifted-legacy step (the Feistel toy — the only frame
 * that ever lacked port I/O) was gone. The invariant in
 * `tests/requires-ported-dispatch.test.ts` pins that every shipped leaf is
 * port-native, so this view is now unconditional.
 */
const FrameStateView = (props: { frame: TraceFrame }) => <PortFlowView frame={props.frame} />;

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

/**
 * Resolve the canonical-default key for any Algorithm. Branches over the
 * cipher / hash tables. Used by the cross-category smart-swap in
 * `changeCategory` and the document-load smart-swap in `applyDocument`
 * (Slice 2.10c, 2026-05-25). Each table is a `Record` keyed exhaustively
 * over its family — no fallback needed.
 */
const algorithmDefaultKey = (a: Algorithm): Uint8Array => {
  if (isHash(a)) return DEFAULT_KEY_BYTES_BY_HASH[a];
  if (isAsymmetric(a)) return DEFAULT_KEY_BYTES_BY_ASYMMETRIC[a]; // empty — no key
  return DEFAULT_KEY_BYTES_BY_CIPHER[a];
};

/**
 * Resolve the canonical-default plaintext / message for any Algorithm.
 * Symmetric to `algorithmDefaultKey` above. SHA-256's default is "abc"
 * (FIPS 180-4 §A.1 single-block KAT), so first-time hash users land on
 * the textbook digest.
 */
const algorithmDefaultPt = (a: Algorithm): Uint8Array => {
  if (isHash(a)) return DEFAULT_PT_BYTES_BY_HASH[a];
  // RSA's "plaintext" default is its encrypt-mode message; the decrypt-mode
  // ciphertext default is swapped in mode-aware by `changeMode` (mirrors how
  // `DEFAULT_CT_BYTES_BY_CIPHER` is consulted for ciphers in decrypt mode).
  if (isAsymmetric(a)) return DEFAULT_PT_BYTES_BY_ASYMMETRIC[a];
  return DEFAULT_PT_BYTES_BY_CIPHER[a];
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
  const name = CIPHER_LABELS[cipher];

  // A cipher with no core is single-block only and takes no padding, so its
  // whole story is "exactly one block".
  if (!hasBlockCipherCore(cipher)) {
    return `${label}: must be exactly ${min} bytes (one ${name} block); got ${got}.`;
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
    return `${label}: ${name}-CTR accepts ${range}; got ${got}. (No padding needed; cap is the UI's MAX_BLOCKS_UI for trace browsability.)`;
  }

  // Single-block, with scheme-specific hints.
  if (mode === "decrypt") {
    return `${label}: must be exactly ${min} bytes (one ${name} block); got ${got}.`;
  }
  switch (scheme) {
    case "pkcs7":
      return `${label}: PKCS#7 input must be ${range}; got ${got}. (A ${max + 1}-byte input would need a second padding block — switch to ECB/CBC mode for multi-block input.)`;
    case "iso7816-4":
      return `${label}: ISO 7816-4 input must be ${range}; got ${got}. (Like PKCS#7, this scheme always appends at least one byte — the 0x80 sentinel — so a ${max + 1}-byte input would need a second block. Switch to ECB/CBC mode for multi-block input.)`;
    case "zero-pad":
      if (got < min) {
        return `${label}: Zero-pad input must be ${range}; got ${got}. (Length 0 would produce an empty padded block, which has no bytes for ${name} to act on.)`;
      }
      return `${label}: Zero-pad input must be ${range}; got ${got}. (A ${max + 1}-byte input would need a second padding block — switch to ECB/CBC mode for multi-block input.)`;
    case "none":
      return `${label}: must be ${range}; got ${got}.`;
  }
};
