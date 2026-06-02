/**
 * Port-aware inspector view for pure port-native trace frames
 * (Slice 2.9b of the universal-port-dataflow plan —
 * `docs/plans/slice-2-9-port-aware-provenance.md`).
 *
 * **What this renders.** A vertical stack of port rows: every entry in
 * `frame.portInputs` becomes one input row, followed by every entry in
 * `frame.portOutputs` as an output row. Each row carries the port's name
 * (left-aligned label) and a cell strip — one `.bytes-cell` per byte —
 * the shared byte-cell primitive the step strip renders too.
 *
 * **Why this exists.** Pure port-native steps (SHA-256's `xor@1`,
 * `add-mod-32@1`, `rotate-bits-right@1`, etc.) leave the threaded state a
 * passthrough — the actual transformation happens in the port I/O, not in
 * state. A `"state"`-keyed view would render nothing for them (they carry no
 * `"state"` port — `framePrimaryOutBytes` returns null since the field retired
 * in Slice 5.3e Batch 4); `PortFlowView` surfaces what the step actually
 * computed by reading the port-I/O captured on the frame in Slice 2.9a.
 *
 * **What this does NOT do.** Cells are display-only — no hover, no click,
 * no cell-level provenance highlighting. The cell-level provenance hover an
 * earlier 2.9c-e draft proposed was formally DEFERRED (see
 * `docs/plans/slice-2-9-port-aware-provenance.md`): the graph already answers
 * port-level provenance (follow the edge to the producer, inspect its value),
 * and the value inspector / step strip / RunExplorer now resolve each leaf's
 * real port by name, so the marginal byte-level highlight wasn't worth a
 * bespoke surface (advisor verdict 2026-05-27: cells deliver ~80% of the
 * pedagogical value). The byte-format toggle IS honored — that's already
 * cheap and the cells are otherwise unreadable without it.
 *
 * **Port-native predicate** (`isPortNativeFrame`): a frame is port-native
 * iff `portInputs !== undefined || portOutputs !== undefined`. The runtime
 * populates these fields whenever the registration has NO `legacy` executor
 * (the port-capture gate at ~`runtime.ts:767`), so BOTH pure port-native
 * steps AND the hybrid-ported steps (meta retained, legacy dropped) carry
 * port I/O. Since Slice 5.2 that hybrid set is the monolithic key-schedule
 * oracle executors (AES/Speck/Serpent/DES) + the padding family; the oracle
 * frames are no longer emitted by any shipped spec (every schedule decomposed
 * into port-native primitives in K1–K4), so in practice padding is the only
 * hybrid family that lands here. Every shipped leaf is
 * port-native (pinned by `tests/requires-ported-dispatch.test.ts`), so once
 * Slice 5.3e retired the last lifted-legacy step (the Feistel toy) + its
 * `BytesView` fallback, `FrameStateView` renders this view unconditionally
 * and the predicate is now informational. Steps that publish only outputs
 * (constants) or only inputs (sinks) still match via the `||`.
 */

import { formatByte } from "@/core/format";
import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo } from "solid-js";
import { useByteFormat } from "../stores/format";

/**
 * True iff the runtime captured port I/O on this frame (the port-capture
 * gate at ~`runtime.ts:767`). Since Slice 5.3e every shipped frame is
 * port-native and `FrameStateView` renders `PortFlowView` unconditionally,
 * so this is now an informational/contract predicate rather than a live
 * render-dispatch gate — kept exported as the named port-native contract.
 */
export const isPortNativeFrame = (frame: TraceFrame): boolean =>
  frame.portInputs !== undefined || frame.portOutputs !== undefined;

type Props = {
  frame: TraceFrame;
};

export const PortFlowView = (props: Props) => {
  // Materialize port lists once per frame change. Map iteration is
  // insertion order in ES, and the runtime inserts in port-declaration
  // order (see `runtime.ts:502-505`), so the row order matches the
  // executor's contract authoring order — no sort needed. `createMemo`
  // because both lists are read TWICE in JSX below (`<Show when>` +
  // `<For each>`) and we don't want to allocate a fresh array per read.
  const inputRows = createMemo<readonly [string, Uint8Array][]>(() => {
    const m = props.frame.portInputs;
    if (m === undefined) return EMPTY_PORT_ROWS;
    return Array.from(m);
  });
  const outputRows = createMemo<readonly [string, Uint8Array][]>(() => {
    const m = props.frame.portOutputs;
    if (m === undefined) return EMPTY_PORT_ROWS;
    return Array.from(m);
  });

  return (
    <div class="port-flow-view">
      {/* Inputs section. Skipped entirely when there are no input
          ports (e.g. `constant-load@1` — outputs-only). */}
      <Show when={inputRows().length > 0}>
        <div class="port-flow-section" data-section="inputs">
          <For each={inputRows()}>
            {([portName, bytes]) => <PortRow side="input" portName={portName} bytes={bytes} />}
          </For>
        </div>
      </Show>

      {/* Separator: rendered only when BOTH sides have ports. A
          single-sided port frame would otherwise show a lone divider
          floating above or below the only section. */}
      <Show when={inputRows().length > 0 && outputRows().length > 0}>
        <div class="port-flow-divider" aria-hidden="true" />
      </Show>

      {/* Outputs section. Symmetric to inputs — skipped on a
          (hypothetical) sink leaf with no outputs. */}
      <Show when={outputRows().length > 0}>
        <div class="port-flow-section" data-section="outputs">
          <For each={outputRows()}>
            {([portName, bytes]) => <PortRow side="output" portName={portName} bytes={bytes} />}
          </For>
        </div>
      </Show>
    </div>
  );
};

/** Shared sentinel so the "no port fields" branch of the memos never
 *  produces a new array — keeps Solid's reactive equality cheap when
 *  the user scrubs between two port-empty frames in a row. */
const EMPTY_PORT_ROWS: readonly [string, Uint8Array][] = [];

/**
 * One labelled row of byte cells for a single port.
 *
 * Cells reuse `.bytes-cell` so visual rhythm matches BytesView's flat
 * rows. The label sits to the left at fixed width so multi-row stacks
 * align column-wise (operand0 / operand1 / … cells start at the same x).
 *
 * Byte-format toggle (`useByteFormat`) is read inline on each cell so a
 * format flip re-renders text without unmounting the row.
 */
const PortRow = (props: { side: "input" | "output"; portName: string; bytes: Uint8Array }) => {
  const fmt = useByteFormat();
  // Materialize byte indices once for the For loop. Keyed by index
  // (which is monotonic and stable across re-renders for a given
  // byte length) so Solid re-uses cell nodes when scrubbing between
  // same-length frames. `createMemo` because the array is read twice
  // (`<Show when={...length > 0}>` + `<For each>`).
  const cells = createMemo<readonly { index: number; byte: number }[]>(() => {
    const out: { index: number; byte: number }[] = [];
    for (let i = 0; i < props.bytes.length; i++) {
      out.push({ index: i, byte: props.bytes[i] ?? 0 });
    }
    return out;
  });

  return (
    <div class="port-row" data-side={props.side} data-port-name={props.portName}>
      <div class="port-label" title={`${props.side} port`}>
        {props.portName}
        <span class="port-row-count"> ({props.bytes.length} bytes)</span>
      </div>
      <div class="port-row-cells">
        <Show when={props.bytes.length > 0} fallback={<span class="muted small">(empty)</span>}>
          <For each={cells()}>
            {(cell) => (
              <div class="bytes-cell" title={`index ${cell.index}`}>
                {formatByte(cell.byte, fmt())}
              </div>
            )}
          </For>
        </Show>
      </div>
    </div>
  );
};
