/**
 * Feistel track-context panel — Phase 5a of `docs/plans/des-feistel.md`.
 *
 * Renders ONLY when the active frame is inside a Feistel round body
 * (`frame.branchPath` non-empty). Three sections:
 *
 *   1. Round entry: the round's input state split into L and R halves
 *      (e.g. for DES: L_in = bytes [0..3], R_in = bytes [4..7]).
 *   2. Right now: the currently-active track's evolving state. The
 *      OTHER track is rendered muted to reinforce "this track is the
 *      one whose body is executing the current step; the other one
 *      passes through".
 *   3. Round output: the post-rejoin halves (new_L, new_R) that become
 *      the next round's input.
 *
 * The round-entry and round-output values are reconstructed from the
 * round's rejoin synthetic frame, which the runtime always emits
 * (deterministic id: `{roundId}:rejoin`). The rejoin frame's
 * `params.L_in` / `params.R_in` give round entry; its `stateAfter`
 * (split at L_in.length) gives round output. No need to walk the
 * trace's predecessor chain — the rejoin frame is the single
 * authoritative source.
 *
 * Cipher-agnostic: works for any Feistel cipher, not just DES, because
 * the inputs come from the spec primitive's runtime stash rather than
 * any DES-specific knowledge. TEA/XTEA/Twofish would render the same
 * shape without modification.
 */

import type { BytesState, TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useByteFormat } from "../stores/format";
import { useProvenanceHover } from "../stores/provenance-hover";
import { getTrace, useTraceVersion } from "../stores/trace";
import { ByteRow } from "./byte-row";

type Props = {
  frame: TraceFrame;
};

/**
 * Round context extracted from the trace: the round id, the two
 * inputs (L_in / R_in), the two outputs (new_L / new_R), and the
 * current track name. Null when the frame isn't inside a Feistel
 * round (no branchPath) or when the round's rejoin frame isn't in
 * the trace (shouldn't happen — runtime always emits one).
 */
type RoundContext = {
  readonly roundId: string;
  readonly currentTrackName: string;
  readonly L_in: Uint8Array;
  readonly R_in: Uint8Array;
  readonly new_L: Uint8Array;
  readonly new_R: Uint8Array;
};

const extractRoundContext = (
  frame: TraceFrame,
  traceFrames: readonly TraceFrame[],
): RoundContext | null => {
  const branchPath = frame.branchPath;
  if (!branchPath || branchPath.length === 0) return null;
  // The current track is the innermost (last) entry in branchPath.
  // For DES: ["R"] when inside R-track's expand-R, etc. Nested Feistel
  // (none planned today) would push more entries; we render only the
  // innermost since that's "what's executing now."
  const currentTrackName = branchPath[branchPath.length - 1];
  if (currentTrackName === undefined) return null;

  // Round id is the last element of frame.path that names a round.
  // The runtime composes path as [...ancestors, roundId] before
  // descending into a track's children, so path's last segment is
  // the round we're inside. (Nested round-inside-round isn't shipped;
  // if it ever lands, the lookup logic still works — branchPath's
  // depth matches the spec's nesting.)
  const roundId = frame.path[frame.path.length - 1];
  if (roundId === undefined) return null;

  // Find the rejoin frame for this round. Its stepId is
  // `{roundId}:rejoin` modulo any outer suffixes (`:b{i}` if the
  // round is inside an iterate). We compare against the unsuffixed
  // form by checking startsWith.
  const rejoinPrefix = `${roundId}:rejoin`;
  // If we're inside an iterate, prefer the rejoin frame that has the
  // same blockIndex as the current frame; otherwise any matching
  // rejoin works.
  const blockIdx = frame.blockIndex;
  const rejoinFrame = traceFrames.find((f) => {
    if (!f.stepId.startsWith(rejoinPrefix)) return false;
    if (blockIdx === undefined) return f.blockIndex === undefined;
    return f.blockIndex === blockIdx;
  });
  if (!rejoinFrame) return null;

  // Pull L_in / R_in from the rejoin frame's params (stashed by the
  // runtime in Phase 5c). Defensive: a stale fixture or schema drift
  // could omit them, in which case the panel quietly hides.
  const params = rejoinFrame.params;
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const p = params as Record<string, unknown>;
  const isByteArr = (v: unknown): v is number[] =>
    Array.isArray(v) && v.every((n) => typeof n === "number");
  if (!isByteArr(p.L_in) || !isByteArr(p.R_in)) return null;
  const L_in = new Uint8Array(p.L_in);
  const R_in = new Uint8Array(p.R_in);

  // new_L / new_R come from splitting rejoin.stateAfter at L_in.length.
  if (rejoinFrame.stateAfter.shape !== "bytes") return null;
  const after = (rejoinFrame.stateAfter as BytesState).bytes;
  if (after.length < L_in.length) return null;
  return {
    roundId,
    currentTrackName,
    L_in,
    R_in,
    new_L: after.slice(0, L_in.length),
    new_R: after.slice(L_in.length),
  };
};

export const FeistelTrackContext = (props: Props) => {
  const fmt = useByteFormat();
  const version = useTraceVersion();
  // Subscribe to the shared provenance-hover signal once. Reading the
  // thunk inside the memo body would re-bind a fresh subscription on
  // each memo execution (the same gotcha the RoundKeyPanel comment
  // calls out at line 173).
  const hover = useProvenanceHover();

  const context = createMemo<RoundContext | null>(() => {
    void version();
    const t = getTrace();
    if (!t) return null;
    return extractRoundContext(props.frame, t.frames);
  });

  // The "right now" track's current bytes come from frame.stateAfter
  // — that's the track's evolving state at this step. For empty tracks
  // (DES's L passthrough) we never land on a frame inside them, so
  // there's no "right now" case for an empty track.
  const currentTrackBytes = createMemo<Uint8Array | null>(() => {
    const after = props.frame.stateAfter;
    if (after.shape !== "bytes") return null;
    return after.bytes;
  });

  // ─── Phase 5a polish: cross-panel provenance overlay ─────────────────
  //
  // When the user hovers an `after` cell in the active step's MatrixView
  // or BytesView, the shared `useProvenanceHover` signal carries the
  // resulting `ProvenanceSource[]`. This panel paints two derived
  // highlights:
  //
  //   1. `roundEntryHighlights` — `before-cell` sources mapped onto the
  //      CURRENT track's round-entry row. Only meaningful when the
  //      active frame is the FIRST step of the track (i.e. its
  //      `stateBefore` matches the round-entry slice for that track) —
  //      `before-cell` indices then map 1:1 to round-entry indices.
  //      For later track steps `stateBefore` is the post-prior-leaf
  //      state (e.g. DES s-boxes sees 6-byte E(R)⊕K_i, not R_in), so
  //      indices wouldn't align; we suppress the highlight rather than
  //      paint something misleading. Transitive provenance through
  //      prior track leaves is deliberately out of scope.
  //
  //   2. `currentRowHighlight` — the single hovered cell, mirrored
  //      onto the "right now" row (which renders `stateAfter`, i.e.
  //      the same buffer the cell-under-cursor lives in). Tightens
  //      the cross-panel coupling so the user sees "this is the cell
  //      you're pointing at, also rendered here in the round-as-a-whole
  //      view".
  //
  // Both gates check `hover.stepId === frame.stepId` so a stale hover
  // from a prior scrub can't paint cells here (same scope guard the
  // RoundKeyPanel and the {Bytes,Matrix}View `before` rows use).
  const roundEntryHighlights = createMemo<ReadonlySet<number>>(() => {
    const h = hover();
    if (!h || h.stepId !== props.frame.stepId) return EMPTY_INDEX_SET;
    const ctx = context();
    if (!ctx) return EMPTY_INDEX_SET;
    const before = props.frame.stateBefore;
    if (before.shape !== "bytes") return EMPTY_INDEX_SET;
    // Pick the current track's round-entry slice; if `stateBefore`
    // doesn't byte-match it, this is a later track step (or a track
    // whose first step took a sliced input) — bail out.
    const roundEntry = ctx.currentTrackName === "L" ? ctx.L_in : ctx.R_in;
    if (!bytesEqual(before.bytes, roundEntry)) return EMPTY_INDEX_SET;
    const out = new Set<number>();
    for (const src of h.sources) {
      if (src.kind === "before-cell") out.add(src.index);
    }
    return out;
  });

  const currentRowHighlight = createMemo<ReadonlySet<number>>(() => {
    const h = hover();
    if (!h || h.stepId !== props.frame.stepId) return EMPTY_INDEX_SET;
    // The hovered cell is by definition inside `stateAfter` — render it
    // back onto the "right now" row's single cell of the same index.
    return new Set([h.afterCellIndex]);
  });

  return (
    <Show when={context()}>
      {(getCtx) => (
        <section class="feistel-track-context" aria-label="feistel round context">
          <div class="feistel-context-header">
            <span class="feistel-context-round">{getCtx().roundId}</span>
            <span class="feistel-context-current-label muted small">
              currently inside <code>{getCtx().currentTrackName}</code> track
            </span>
          </div>
          <div class="feistel-context-sections">
            <ContextSection
              title="round entry"
              tracks={[
                {
                  name: "L",
                  bytes: getCtx().L_in,
                  isCurrent: getCtx().currentTrackName === "L",
                  highlights:
                    getCtx().currentTrackName === "L" ? roundEntryHighlights() : EMPTY_INDEX_SET,
                },
                {
                  name: "R",
                  bytes: getCtx().R_in,
                  isCurrent: getCtx().currentTrackName === "R",
                  highlights:
                    getCtx().currentTrackName === "R" ? roundEntryHighlights() : EMPTY_INDEX_SET,
                },
              ]}
              fmt={fmt()}
            />
            <Show when={currentTrackBytes()}>
              {(getBytes) => (
                <ContextSection
                  title="right now"
                  tracks={[
                    {
                      name: getCtx().currentTrackName,
                      bytes: getBytes(),
                      isCurrent: true,
                      note: `${shortStepName(props.frame.stepId)} → ${getBytes().length} bytes`,
                      highlights: currentRowHighlight(),
                    },
                  ]}
                  fmt={fmt()}
                />
              )}
            </Show>
            <ContextSection
              title="round output"
              tracks={[
                {
                  name: "L'",
                  bytes: getCtx().new_L,
                  isCurrent: false,
                  highlights: EMPTY_INDEX_SET,
                },
                {
                  name: "R'",
                  bytes: getCtx().new_R,
                  isCurrent: false,
                  highlights: EMPTY_INDEX_SET,
                },
              ]}
              fmt={fmt()}
            />
          </div>
        </section>
      )}
    </Show>
  );
};

/** Allocation-free empty highlight set; shared sentinel so the memos'
 *  "no hover" branch never produces a new object. */
const EMPTY_INDEX_SET: ReadonlySet<number> = new Set();

/** Cheap byte-equality. Used to gate round-entry highlights to frames
 *  whose `stateBefore` IS the round-entry slice. Two Uint8Arrays of the
 *  same length and contents return true; anything else returns false. */
const bytesEqual = (a: Uint8Array, b: Uint8Array): boolean => {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
};

/**
 * Strip runtime suffixes (`:t{name}`, `:b{i}`) off a frame stepId and
 * take the last dot-segment as the short step name (e.g. "expand-R"
 * out of "round.5.expand-R:tR"). Used for the "right now" note.
 */
const shortStepName = (stepId: string): string => {
  const beforeSuffix = stepId.split(":")[0] ?? stepId;
  return beforeSuffix.split(".").pop() ?? beforeSuffix;
};

/**
 * One labelled byte-row group (e.g. "round entry" with its L + R
 * rows). The `isCurrent` flag on a track row drives the color accent
 * so the user can pick out the active track at a glance.
 */
const ContextSection = (props: {
  title: string;
  tracks: ReadonlyArray<{
    name: string;
    bytes: Uint8Array;
    isCurrent: boolean;
    note?: string;
    /** Set of cell indices to outline as provenance sources (Phase 5a
     *  polish). Pass the shared `EMPTY_INDEX_SET` for "no highlights" —
     *  required-not-optional under `exactOptionalPropertyTypes`
     *  because Solid `For` callbacks can't conditionally spread props. */
    highlights: ReadonlySet<number>;
  }>;
  fmt: ReturnType<typeof useByteFormat> extends () => infer R ? R : never;
}) => (
  <div class="feistel-context-section">
    <div class="feistel-context-section-title muted small">{props.title}</div>
    <For each={props.tracks}>
      {(track) => (
        <div
          class="feistel-context-track-row"
          classList={{ "feistel-context-track-current": track.isCurrent }}
        >
          <span class="feistel-context-track-name">{track.name}</span>
          {/* Inline read of `track.highlights` so Solid re-evaluates as
              the active hover changes. `For` callbacks aren't reactive
              scopes — a captured const here would freeze at first
              render (per the CLAUDE.md Solid gotcha). */}
          <ByteRow bytes={track.bytes} fmt={props.fmt} provenanceHighlights={track.highlights} />
          <Show when={track.note}>
            <span class="feistel-context-track-note muted small">{track.note}</span>
          </Show>
        </div>
      )}
    </For>
  </div>
);
