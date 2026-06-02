/**
 * Shared byte-row + byte-formatting helpers. Originally extracted from
 * the (now-retired, K4b 2026-06-02) `KeyScheduleExplorer.tsx`; the
 * surviving consumers are the port-native Feistel views
 * (FeistelRoundBytes / FeistelRecombineView) and the per-frame narration
 * components (`narration/*`), which render byte sequences with the same
 * visual rhythm.
 *
 * `<ByteRow>` renders a horizontal strip of bordered cells (one per
 * byte), each showing the byte in the currently-selected format.
 * Optional `highlightIndex` outlines one cell.
 *
 * `formatBytes` returns a compact `[0x01, 0x02, ...]` string useful
 * inline inside prose paragraphs where a `<ByteRow>` would be too
 * heavyweight. Both consumers (legend prose, narration prose) need
 * the format-aware string form.
 *
 * Style classes (`key-schedule-byte-row`, `key-schedule-byte-cell`,
 * `key-schedule-byte-highlight`) keep the `key-schedule-` prefix as a
 * naming holdover from the retired explorer that first defined them —
 * it is no longer a scope marker (see the CSS note in `app.css`).
 */

import { type ByteFormat, formatByte } from "@/core/format";
import { For } from "solid-js";

export const ByteRow = (props: {
  bytes: Uint8Array;
  fmt: ByteFormat;
  /** Optional index to outline with `.key-schedule-byte-highlight`. */
  highlightIndex?: number;
}) => (
  <div class="key-schedule-byte-row">
    <For each={Array.from(props.bytes)}>
      {(b, i) => (
        <div
          class="key-schedule-byte-cell"
          classList={{
            "key-schedule-byte-highlight":
              props.highlightIndex !== undefined && i() === props.highlightIndex,
          }}
        >
          {formatByte(b, props.fmt)}
        </div>
      )}
    </For>
  </div>
);

/**
 * Format a byte sequence as a bracketed list, respecting the byte-format
 * toggle. Used inline in value-prose text where a denser representation
 * than `<ByteRow>` (which renders bordered cells) is wanted but the
 * text still needs to react to format changes.
 */
export const formatBytes = (bytes: Uint8Array, fmt: ByteFormat): string =>
  `[${Array.from(bytes)
    .map((b) => formatByte(b, fmt))
    .join(", ")}]`;

/** Inline single-byte formatter — sugar around `formatByte` for symmetry. */
export const formatByteInline = (b: number, fmt: ByteFormat): string => formatByte(b, fmt);
