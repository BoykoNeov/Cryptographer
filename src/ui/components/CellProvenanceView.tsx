/**
 * Always-on cell-provenance surface for the graph leaf inspector (Tier B of the
 * leaf-inspector expanders, 2026-07-13).
 *
 * `PortFlowView` already lights up an output cell's input sources ON HOVER; this
 * shows the WHOLE map statically so a learner reads the wiring at a glance
 * without pointing at every byte. The classification is pure index math from
 * `src/core/cell-provenance-summary.ts` (`summarizeCellProvenance`), which in
 * turn reads the same `port-provenance.ts` fns the hover uses — one source of
 * truth, no value dependence.
 *
 * Four render shapes, one per summary variant:
 *   - `same-index`  → a single sentence ("each output byte ← the same-position
 *      input byte(s): operand0[i], operand1[i]"). Collapses xor/and/not/etc.
 *   - `offset`      → a single sentence ("output[i] ← input[i + 8]").
 *   - `per-cell`    → one row per output cell (permute / concat / split-bytes /
 *      MixColumns) with the source index(es), the GF `×coeff` badge where the
 *      provenance carries one, and the source byte VALUE (format-aware) as a
 *      muted suffix — indices are the payload, values are context.
 *   - `none`        → nothing (the parent guards the expander out).
 *
 * The component never renders when `summary.kind === "none"`; the caller in
 * `GraphView` only mounts it for a resolvable-provenance frame.
 */

import type { CellProvenanceSummary } from "@/core/cell-provenance-summary";
import { formatByte } from "@/core/format";
import type { ProvenanceCell } from "@/core/port-provenance";
import type { TraceFrame } from "@/core/types";
import { For, Show } from "solid-js";
import { useByteFormat } from "../stores/format";

type Props = {
  frame: TraceFrame;
  summary: CellProvenanceSummary;
};

/** Render a port + index reference (`operand0[3]`) — the shared inline atom. */
const cellRef = (portName: string, cellIndex: number): string => `${portName}[${cellIndex}]`;

export const CellProvenanceView = (props: Props) => {
  const fmt = useByteFormat();

  // Fetch a source cell's byte value from the frame's inputs for the muted
  // value suffix. Returns null on any miss (never throws — a half-wired operand
  // simply shows no value).
  const sourceByte = (portName: string, cellIndex: number): number | null => {
    const bytes = props.frame.portInputs?.get(portName);
    if (bytes === undefined || cellIndex < 0 || cellIndex >= bytes.length) return null;
    return bytes[cellIndex] ?? null;
  };

  return (
    <div class="cell-provenance-view">
      <Show when={props.summary.kind === "same-index" ? props.summary : null}>
        {(s) => (
          <p class="cell-provenance-summary-line">
            Each output byte keeps its position — <code>output[i]</code> comes from the
            same-position input byte
            {s().ports.length > 1 ? "s" : ""}:{" "}
            <For each={s().ports}>
              {(port, i) => (
                <>
                  <Show when={i() > 0}>{", "}</Show>
                  {/* Symbolic index `i` — this is the collapsed uniform form, so
                      the same relation holds for every position. */}
                  <code>{port}[i]</code>
                </>
              )}
            </For>{" "}
            <span class="muted small">({s().length} bytes)</span>
          </p>
        )}
      </Show>

      <Show when={props.summary.kind === "offset" ? props.summary : null}>
        {(s) => (
          <p class="cell-provenance-summary-line">
            A contiguous window — <code>output[i]</code> comes from{" "}
            <code>
              {s().port}[i + {s().offset}]
            </code>{" "}
            <span class="muted small">({s().length} bytes)</span>
          </p>
        )}
      </Show>

      <Show when={props.summary.kind === "per-cell" ? props.summary : null}>
        {(s) => (
          <ul class="cell-provenance-rows">
            <For each={s().rows}>
              {(row) => (
                <li class="cell-provenance-row" data-out-port={row.outPort}>
                  <code class="cell-provenance-out">{cellRef(row.outPort, row.outIndex)}</code>
                  <span class="cell-provenance-arrow" aria-hidden="true">
                    {" ← "}
                  </span>
                  <Show
                    when={row.sources.length > 0}
                    fallback={<span class="muted small">(no input source)</span>}
                  >
                    <For each={row.sources}>
                      {(src: ProvenanceCell, i) => (
                        <>
                          <Show when={i() > 0}>{", "}</Show>
                          <span class="cell-provenance-src">
                            <code>{cellRef(src.portName, src.cellIndex)}</code>
                            <Show when={src.label}>
                              {(label) => <span class="cell-provenance-coeff">{label()}</span>}
                            </Show>
                            <Show when={sourceByte(src.portName, src.cellIndex) !== null}>
                              <span class="muted small cell-provenance-val">
                                {formatByte(sourceByte(src.portName, src.cellIndex) ?? 0, fmt())}
                              </span>
                            </Show>
                          </span>
                        </>
                      )}
                    </For>
                  </Show>
                </li>
              )}
            </For>
          </ul>
        )}
      </Show>
    </div>
  );
};
