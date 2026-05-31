/**
 * Round-key side-by-side panel. Linear-mode pedagogy addition (Phase 1 of
 * the immutable-doodling-quokka plan): surface the entire round-key
 * schedule at once so the user sees structural patterns currently invisible
 * when only the consumed K_i is rendered per AddRoundKey frame.
 *
 * Cipher-agnostic by design. The panel scans `trace.finalAux` for entries
 * matching `${prefix}.${index}` whose values are `Uint8Array`, groups them,
 * and renders each group as a ribbon. This catches:
 *
 *   - AES: `roundKey.0` … `roundKey.{Nr}` — 16-byte keys → 4×4 grids via TinyMatrix
 *   - Serpent: `roundKey.0` … `roundKey.32` — same 16-byte path
 *   - Speck32/64: `roundKey.0` … `roundKey.21` — 2-byte subkeys → 2-cell strips
 *
 * Highlight semantics: any K_i whose canonical aux name (`${prefix}.${index}`)
 * appears in the current frame's `auxRead` map gets the `.round-key-cell-current`
 * outline. So during AddRoundKey round 3, `K_3` lights up; key-expansion frames
 * highlight nothing because they only *write* aux.
 *
 * The panel is hidden via a `<Show>` guard when no qualifying sequences are
 * found (e.g. on very-early boot before any trace, or for a hypothetical
 * future cipher with no schedulable aux). Stays empty rather than rendering
 * an awkward placeholder.
 */

import { type ByteFormat, formatByte } from "@/core/format";
import type { Aux, TraceFrame } from "@/core/types";
import { For, Show, createEffect, createMemo, createSignal, on } from "solid-js";
import { useByteFormat } from "../stores/format";
import { useSpec } from "../stores/spec";
import { useTraceFinalAux } from "../stores/trace";
import { TinyMatrix } from "./TinyMatrix";

type Props = {
  /**
   * Currently selected frame. Used to compute which aux entries the step
   * consumes — those `K_i` get the "current" outline. Null when no frame
   * is selected (boot, or a step that hasn't executed yet).
   */
  frame: TraceFrame | null;
};

/**
 * A contiguous-or-mostly-contiguous sequence of round keys in aux, identified
 * by a common name prefix (`roundKey` is the convention every cipher uses,
 * but the panel doesn't hardcode it — anything matching `prefix.N` qualifies).
 */
type RoundKeySequence = {
  /** The aux-name prefix shared by every entry in the sequence ("roundKey"). */
  readonly prefix: string;
  /** Byte length common to every entry — uniform within a sequence. */
  readonly byteLength: number;
  /** Entries sorted by index ascending. */
  readonly entries: readonly { readonly index: number; readonly bytes: Uint8Array }[];
};

// Matches "prefix.N" with N as a non-negative integer. Captures the prefix
// in group 1 and the index in group 2. Allows nested-dot prefixes (e.g.
// `cipher.roundKey.3` would group under `cipher.roundKey`) — greedy `.+`
// gives the trailing `.N` the smallest match.
const PREFIX_INDEX_RE = /^(.+)\.(\d+)$/;

/**
 * User override for the panel's collapsed state. Module-scope so a single
 * click "sticks" across frame scrubs within one spec session, but resets
 * to `null` (use frame-derived default) on spec change. `null` means
 * "no explicit user choice — derive from current frame relevance."
 *
 * The two-source design — frame-derived default + user override —
 * matches the UX the user asked for during 2026-05-18 Phase 1 smoke:
 * the panel is auto-visible on key-expansion and AddRoundKey frames
 * (when it's *about* something the user is looking at), auto-collapsed
 * on others (so it doesn't crowd the much-larger ParamEditor that
 * follows), but always overridable.
 */
const [overrideExpanded, setOverrideExpanded] = createSignal<boolean | null>(null);

/**
 * Test-only: clear the override so cases don't leak state.
 */
export const __resetRoundKeyPanelOverrideForTests = (): void => {
  setOverrideExpanded(null);
};

/**
 * Is the current frame one for which the round-key panel is pedagogically
 * "about" the work the user is looking at? A frame is relevant when it
 * either CONSUMES or PRODUCES at least one of the detected schedule's
 * keys:
 *
 *   - Producers: key-schedule / key-expansion frames write `prefix.N`
 *     entries to aux. Their `auxWritten` map contains the schedule.
 *   - Consumers: AddRoundKey-style frames read a specific `K_i` via
 *     `auxRead`. The schedule is being mixed in right now.
 *
 * The read-or-write check is cipher-agnostic by construction — no
 * hardcoded list of step types, no dependency on the key-schedule-sim
 * registry (which only knows AES + Serpent today; Speck's
 * `speck.key-schedule@1` would otherwise be misclassified). A future
 * cipher whose schedule uses `prefix.N` aux naming automatically counts
 * on both sides.
 *
 * Returns `false` when no frame is selected.
 */
const isRelevantFrame = (
  frame: TraceFrame | null,
  sequences: readonly RoundKeySequence[],
): boolean => {
  if (!frame) return false;
  for (const seq of sequences) {
    for (const entry of seq.entries) {
      const name = `${seq.prefix}.${entry.index}`;
      if (frame.auxRead.has(name)) return true;
      if (frame.auxWritten.has(name)) return true;
    }
  }
  return false;
};

/**
 * Walk the aux map and find every `prefix.N`-pattern sequence whose values
 * are uniform-length `Uint8Array` and number at least 2. Two-entry minimum
 * because a single `roundKey.0` could be anything (an IV, a counter seed,
 * any one-off byte buffer); panels are about *schedules*.
 *
 * Returns sequences sorted by prefix name for deterministic render order
 * across re-runs. Callers should `<Show when={result.length > 0}>` to hide
 * the panel when nothing qualifies.
 */
export const detectRoundKeySequences = (aux: Aux): RoundKeySequence[] => {
  const groups = new Map<string, { index: number; bytes: Uint8Array }[]>();
  for (const [auxName, value] of aux.entries()) {
    if (!(value instanceof Uint8Array)) continue;
    const m = PREFIX_INDEX_RE.exec(auxName);
    if (!m) continue;
    const prefix = m[1];
    const indexStr = m[2];
    if (prefix === undefined || indexStr === undefined) continue;
    const index = Number.parseInt(indexStr, 10);
    if (!Number.isInteger(index) || index < 0) continue;
    let bucket = groups.get(prefix);
    if (bucket === undefined) {
      bucket = [];
      groups.set(prefix, bucket);
    }
    bucket.push({ index, bytes: value });
  }

  const out: RoundKeySequence[] = [];
  for (const [prefix, entries] of groups) {
    if (entries.length < 2) continue;
    entries.sort((a, b) => a.index - b.index);
    const byteLength = entries[0]?.bytes.length ?? 0;
    // Reject mixed-length groups. They can't render as a uniform ribbon, and
    // they're unlikely to be a real "schedule" — more likely two unrelated
    // aux entries that happened to share a prefix.
    if (!entries.every((e) => e.bytes.length === byteLength)) continue;
    out.push({ prefix, byteLength, entries });
  }
  out.sort((a, b) => a.prefix.localeCompare(b.prefix));
  return out;
};

export const RoundKeyPanel = (props: Props) => {
  const finalAux = useTraceFinalAux();
  const fmt = useByteFormat();
  const spec = useSpec();

  // Spec change resets the user override so a fresh cipher inherits the
  // frame-derived default. `defer: true` skips the initial firing — only
  // an actual *change* should clear the override. Without defer, mounting
  // the component would immediately blow away an override set by some
  // earlier session (which is fine today, but the explicit defer keeps
  // the contract honest if a future caller threads override state in).
  createEffect(
    on(
      () => spec().id,
      () => setOverrideExpanded(null),
      { defer: true },
    ),
  );

  // Detect qualifying sequences from the post-run aux map. Tracks the trace
  // version via `useTraceFinalAux`, so re-runs invalidate this memo cleanly.
  const sequences = createMemo<readonly RoundKeySequence[]>(() => {
    const aux = finalAux();
    if (!aux) return [];
    return detectRoundKeySequences(aux);
  });

  // Combined expanded-state: user override wins when set, otherwise fall
  // back to whether the current frame is "about" the schedule.
  const expanded = createMemo<boolean>(() => {
    const override = overrideExpanded();
    if (override !== null) return override;
    return isRelevantFrame(props.frame, sequences());
  });

  const toggleExpanded = (): void => {
    setOverrideExpanded(!expanded());
  };

  // Set of aux names the current frame consumed via auxRead — fast O(1)
  // membership check per cell to decide the "current" outline. Empty when
  // no frame is selected or when the step only writes aux (key-expansion
  // frames consume nothing under this rule, so they'll show no highlight).
  const consumedAuxNames = createMemo<ReadonlySet<string>>(() => {
    const f = props.frame;
    if (!f) return new Set();
    return new Set(f.auxRead.keys());
  });

  return (
    <Show when={sequences().length > 0}>
      <section class="round-key-panel" aria-label="round-key schedule">
        {/* Clickable header — always visible when sequences exist. The
            chevron + text both toggle. Reading `expanded()` inline so the
            label and chevron react to scrubs (when the frame-derived
            default flips) and to clicks (when the override flips). */}
        <button
          type="button"
          class="round-key-panel-header"
          onClick={toggleExpanded}
          aria-expanded={expanded()}
        >
          <span class="round-key-panel-chevron">{expanded() ? "▼" : "▶"}</span>
          <span class="round-key-panel-title">round-key schedule</span>
          <span class="round-key-panel-hint muted small">
            {expanded() ? "click to hide" : "click to show"}
          </span>
        </button>
        <Show when={expanded()}>
          <div class="round-key-panel-body">
            <For each={sequences()}>
              {(seq) => (
                <SequenceRibbon seq={seq} consumedAuxNames={consumedAuxNames()} fmt={fmt()} />
              )}
            </For>
          </div>
        </Show>
      </section>
    </Show>
  );
};

/**
 * One ribbon = one prefix group. Header names the prefix and the
 * `count × byteLength` shape so the user can quickly read "33 × 16B" and
 * recognize Serpent's schedule. The strip below renders each K_i in order.
 */
const SequenceRibbon = (props: {
  seq: RoundKeySequence;
  consumedAuxNames: ReadonlySet<string>;
  fmt: ByteFormat;
}) => (
  <div class="round-key-ribbon">
    <div class="round-key-ribbon-header">
      <span class="round-key-ribbon-prefix">{props.seq.prefix}</span>
      <span class="round-key-ribbon-shape muted small">
        {props.seq.entries.length} × {props.seq.byteLength}B
      </span>
    </div>
    <div class="round-key-ribbon-strip">
      <For each={props.seq.entries}>
        {(entry) => (
          <RoundKeyCell
            prefix={props.seq.prefix}
            entry={entry}
            isCurrent={props.consumedAuxNames.has(`${props.seq.prefix}.${entry.index}`)}
            byteLength={props.seq.byteLength}
            fmt={props.fmt}
          />
        )}
      </For>
    </div>
  </div>
);

/**
 * One cell = one round key (K_i). Shape dispatch by byte length:
 *
 *   - 16 bytes → reuse `TinyMatrix` by wrapping the buffer as a synthetic
 *     `MatrixState`. Saves a duplicate 4×4 renderer. Column-major byte
 *     storage matches both AES and Serpent's round-key layout (Serpent
 *     applies IP last so the bytes line up with the IP'd state).
 *
 *   - any other length → a single-row strip of cells. Covers Speck32/64's
 *     2-byte subkeys and anything else future ciphers throw at it. No
 *     bespoke logic per cipher.
 */
const RoundKeyCell = (props: {
  prefix: string;
  entry: { readonly index: number; readonly bytes: Uint8Array };
  isCurrent: boolean;
  byteLength: number;
  fmt: ByteFormat;
}) => (
  <div
    class="round-key-cell"
    classList={{ "round-key-cell-current": props.isCurrent }}
    title={`${props.prefix}.${props.entry.index}`}
  >
    <div class="round-key-cell-label">
      K<sub>{props.entry.index}</sub>
    </div>
    <Show
      when={props.byteLength === 16}
      fallback={
        <div class="round-key-cell-strip">
          <For each={Array.from(props.entry.bytes)}>
            {(b) => <div class="round-key-cell-byte">{formatByte(b, props.fmt)}</div>}
          </For>
        </div>
      }
    >
      {/* Render the raw 16-byte round-key buffer as a 4×4 grid. TinyMatrix
          takes bytes directly (post-Slice-5.1). */}
      <TinyMatrix bytes={props.entry.bytes} />
    </Show>
  </div>
);
