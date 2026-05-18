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
import { For, Show, createMemo } from "solid-js";
import { useByteFormat } from "../stores/format";
import { useProvenanceHover } from "../stores/provenance-hover";
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
  // Subscribe to the shared provenance-hover signal once. The memo below
  // invokes the thunk to track invalidation; calling `useProvenanceHover()`
  // inside the memo body would re-bind a fresh subscription every
  // memo execution.
  const hover = useProvenanceHover();

  // Detect qualifying sequences from the post-run aux map. Tracks the trace
  // version via `useTraceFinalAux`, so re-runs invalidate this memo cleanly.
  const sequences = createMemo<readonly RoundKeySequence[]>(() => {
    const aux = finalAux();
    if (!aux) return [];
    return detectRoundKeySequences(aux);
  });

  // Set of aux names the current frame consumed via auxRead — fast O(1)
  // membership check per cell to decide the "current" outline. Empty when
  // no frame is selected or when the step only writes aux (key-expansion
  // frames consume nothing under this rule, so they'll show no highlight).
  const consumedAuxNames = createMemo<ReadonlySet<string>>(() => {
    const f = props.frame;
    if (!f) return new Set();
    return new Set(f.auxRead.keys());
  });

  // Map of `${prefix}.${index}` → set of cell indices to outline as
  // provenance sources. Built from the active hover's `aux-cell` sources;
  // gated by stepId so a stale hover from a prior frame can't paint cells
  // here after the user scrubs to a different frame.
  const hoverHighlightsByAuxName = createMemo<ReadonlyMap<string, ReadonlySet<number>>>(() => {
    const h = hover();
    if (!h || !props.frame || h.stepId !== props.frame.stepId) {
      return EMPTY_HIGHLIGHT_MAP;
    }
    const m = new Map<string, Set<number>>();
    for (const src of h.sources) {
      if (src.kind !== "aux-cell") continue;
      let s = m.get(src.auxName);
      if (s === undefined) {
        s = new Set();
        m.set(src.auxName, s);
      }
      s.add(src.index);
    }
    return m;
  });

  return (
    <Show when={sequences().length > 0}>
      <section class="round-key-panel" aria-label="round-key schedule">
        <For each={sequences()}>
          {(seq) => (
            <SequenceRibbon
              seq={seq}
              consumedAuxNames={consumedAuxNames()}
              fmt={fmt()}
              hoverHighlightsByAuxName={hoverHighlightsByAuxName()}
            />
          )}
        </For>
      </section>
    </Show>
  );
};

/** Allocation-free empty highlight map; shared sentinel so the "no hover"
 *  branch never produces a new object. */
const EMPTY_HIGHLIGHT_MAP: ReadonlyMap<string, ReadonlySet<number>> = new Map();

/**
 * One ribbon = one prefix group. Header names the prefix and the
 * `count × byteLength` shape so the user can quickly read "33 × 16B" and
 * recognize Serpent's schedule. The strip below renders each K_i in order.
 */
const SequenceRibbon = (props: {
  seq: RoundKeySequence;
  consumedAuxNames: ReadonlySet<string>;
  fmt: ByteFormat;
  hoverHighlightsByAuxName: ReadonlyMap<string, ReadonlySet<number>>;
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
          // Read `hoverHighlightsByAuxName.get(...)` inline so Solid
          // re-evaluates as the active hover changes. CLAUDE.md gotcha:
          // For callbacks aren't reactive scopes; a captured const here
          // would freeze at first render.
          <RoundKeyCell
            prefix={props.seq.prefix}
            entry={entry}
            isCurrent={props.consumedAuxNames.has(`${props.seq.prefix}.${entry.index}`)}
            byteLength={props.seq.byteLength}
            fmt={props.fmt}
            provenanceHighlights={props.hoverHighlightsByAuxName.get(
              `${props.seq.prefix}.${entry.index}`,
            )}
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
  /**
   * Linear cell indices to outline inside THIS K_i's TinyMatrix (or
   * strip in the fallback path). Required-but-nullable rather than
   * optional so callers can pass the result of `Map.get()` directly
   * without an exactOptionalPropertyTypes-driven spread. The
   * "no hover" case is `undefined`.
   */
  provenanceHighlights: ReadonlySet<number> | undefined;
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
            {(b, i) => (
              <div
                class="round-key-cell-byte"
                classList={{ "provenance-source": !!props.provenanceHighlights?.has(i()) }}
              >
                {formatByte(b, props.fmt)}
              </div>
            )}
          </For>
        </div>
      }
    >
      {/* Wrap the raw 16-byte buffer as a MatrixState for TinyMatrix.
          Cheap synthesis — no copy, just a discriminant + the same buffer
          aliased under the `bytes` field. TinyMatrix's `provenanceHighlights`
          is typed `ReadonlySet<number> | undefined` so we can pass the
          map-lookup result through directly without a conditional wrapper. */}
      <TinyMatrix
        state={{ shape: "matrix4x4-bytes", bytes: props.entry.bytes }}
        provenanceHighlights={props.provenanceHighlights}
      />
    </Show>
  </div>
);
