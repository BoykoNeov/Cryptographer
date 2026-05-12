/**
 * Render a BytesState (variable-length byte sequence) for the trace view.
 * Sibling to MatrixView — same color/highlight scheme, just laid out as a
 * 1×N row of cells that wraps when the sequence is long.
 *
 * Used by frames whose `stateBefore` and/or `stateAfter` are BytesState:
 *   - pkcs7-pad: BytesState (N bytes) → BytesState (N + padLen bytes)
 *   - pkcs7-unpad: BytesState (16) → BytesState (1..15)
 *   - load-block / store-block: rendered on the BytesState side via the
 *     App's mixed-shape dispatch (matrix on the other side via MatrixView).
 *
 * Length-change highlight: when before.length ≠ after.length, cells beyond
 * the shorter side are flagged so the user can see the expansion (pad) or
 * truncation (unpad) at a glance.
 *
 * Multi-block block grouping: when the longer side of a row pair exceeds one
 * AES block (16 bytes), cells are visually segmented into 16-byte groups
 * with a "Block N" header. This makes ECB-mode pedagogy obvious — identical
 * plaintext blocks produce identical ciphertext blocks, and the reader can
 * spot the repetition at a glance instead of squinting at a single wrapping
 * line. Single-block frames (max length ≤ 16) keep today's flat layout.
 */

import { type ByteFormat, formatByte } from "@/core/format";
import type { BytesState, State } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useByteFormat } from "../stores/format";

type Props = {
  before: BytesState;
  after: BytesState;
  /**
   * Same-stepId after-state from the immediately prior run, when overlay is
   * on. Typed as the wide `State` union so the dispatch is defensive here
   * rather than at the call site — if the prior run had a different shape
   * at this stepId (e.g. user changed padding scheme between runs), we
   * quietly suppress the overlay rather than crashing on byte reads.
   */
  previousAfter?: State | null;
};

/**
 * AES block size in bytes. Block grouping kicks in when a row pair's longer
 * side exceeds this — i.e. the visualization implies "this is multi-block."
 * Today this is hardcoded to 16 because only AES multi-block ciphers reach
 * BytesView with >16 bytes; a future block cipher with a different block
 * size would need to thread the block size through (or the heuristic
 * needs to read the cipher's block size from a store).
 */
const BLOCK_BYTES = 16;

export const BytesView = (props: Props) => {
  const fmt = useByteFormat();

  return (
    <div class="bytes-view">
      {/* Before row: passes after as compareTo so length-delta missing
          cells show up trailing — when after is longer (pad frame), the
          before row makes the expansion visible by ghosting the extra
          positions rather than just being shorter. No `highlightChanged`
          flag because the before row is the baseline. */}
      <Row title="before" bytes={props.before.bytes} format={fmt()} compareTo={props.after.bytes} />
      <Row
        title="after"
        bytes={props.after.bytes}
        format={fmt()}
        compareTo={props.before.bytes}
        highlightChanged
      />
      <Show when={props.previousAfter && props.previousAfter.shape === "bytes"}>
        {(_) => {
          // Narrow once for the prev row; the parent Show only renders
          // this branch when previousAfter is BytesState.
          const prev = props.previousAfter as BytesState;
          return (
            <Row
              title="previous run"
              bytes={prev.bytes}
              format={fmt()}
              compareTo={props.after.bytes}
              highlightDiffPrev
            />
          );
        }}
      </Show>
    </div>
  );
};

/** Per-cell descriptor; produced once and consumed by either the flat or
 * grouped renderer. `missing` means this position only exists on the
 * compareTo side (the row is shorter); `flagged` is "different from
 * compareTo" — interpretation (changed vs diff-vs-prev) is up to the caller's
 * `highlightChanged` / `highlightDiffPrev` flags. */
type Cell = { index: number; byte: number; flagged: boolean; missing: boolean };

const Row = (props: {
  title: string;
  bytes: Uint8Array;
  format: ByteFormat;
  /**
   * When provided, cells at positions where `bytes[i] !== compareTo[i]` (or
   * either side is missing) are flagged with the highlight class. The two
   * arrays may differ in length — out-of-bounds reads on the shorter side
   * are treated as "this cell didn't exist before/after", which is itself
   * a highlight-worthy change.
   */
  compareTo?: Uint8Array;
  highlightChanged?: boolean;
  highlightDiffPrev?: boolean;
}) => {
  // Materialize cell descriptors once per render so the For loop's keyed
  // reactivity stays cheap. The byte format is read inside JSX (not here)
  // so a format toggle still re-renders the labels.
  const cells = createMemo<Cell[]>(() => {
    const out: Cell[] = [];
    const len = props.bytes.length;
    for (let i = 0; i < len; i++) {
      const b = props.bytes[i] ?? 0;
      let flagged = false;
      if (props.compareTo) {
        // Out-of-range on the compare side = the position was added/removed
        // between the two states. Count that as a difference.
        if (i >= props.compareTo.length) flagged = true;
        else if (props.compareTo[i] !== b) flagged = true;
      }
      out.push({ index: i, byte: b, flagged, missing: false });
    }
    // If the compare side is LONGER than this side, the trailing positions
    // are "missing" cells from this row's perspective — render a placeholder
    // so the user can see the length delta.
    if (props.compareTo && props.compareTo.length > len) {
      for (let i = len; i < props.compareTo.length; i++) {
        out.push({ index: i, byte: 0, flagged: true, missing: true });
      }
    }
    return out;
  });

  /** When the longer side of the row pair exceeds one block, slice the
   * cells into 16-byte groups so multi-block ciphertext reads as discrete
   * blocks. Returns null when grouping isn't appropriate (single block or
   * empty), and the flat-row fallback renders instead. */
  const blockGroups = createMemo<Cell[][] | null>(() => {
    const all = cells();
    const maxLen = Math.max(props.bytes.length, props.compareTo?.length ?? 0);
    if (maxLen <= BLOCK_BYTES) return null;
    const out: Cell[][] = [];
    for (let i = 0; i < all.length; i += BLOCK_BYTES) {
      out.push(all.slice(i, i + BLOCK_BYTES));
    }
    return out;
  });

  /** Cell renderer factored out so the flat and grouped branches stay
   * literally identical in markup. Returning a function is the
   * Solid-friendly way to share JSX between two `For` callbacks without
   * losing prop reactivity. */
  const renderCell = (cell: Cell) => (
    <div
      class="bytes-cell"
      classList={{
        changed: !!props.highlightChanged && cell.flagged,
        "diff-vs-prev": !!props.highlightDiffPrev && cell.flagged,
        "bytes-cell-missing": cell.missing,
      }}
      title={`index ${cell.index}`}
    >
      {/* Inline so a format toggle re-renders. Missing cells (this
          row is shorter than the compare row) render a dim dash. */}
      {cell.missing ? "·" : formatByte(cell.byte, props.format)}
    </div>
  );

  return (
    <div class="bytes-row-block">
      <div class="grid-title">
        {props.title}
        <span class="bytes-row-count"> ({props.bytes.length} bytes)</span>
      </div>
      <div class="bytes-row">
        <Show
          when={props.bytes.length > 0 || props.compareTo}
          fallback={<span class="muted small">(empty)</span>}
        >
          <Show when={blockGroups()} fallback={<For each={cells()}>{renderCell}</For>}>
            {(getGroups) => (
              <For each={getGroups()}>
                {(group, gi) => (
                  <div class="bytes-block-group">
                    {/* 1-based label to match BlockBadge's "Block N of M". */}
                    <div class="bytes-block-label">Block {gi() + 1}</div>
                    <div class="bytes-block-cells">
                      <For each={group}>{renderCell}</For>
                    </div>
                  </div>
                )}
              </For>
            )}
          </Show>
        </Show>
      </div>
    </div>
  );
};
