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
 * **Cell-level provenance hover (inspector-cell-hover plan, Slice 2,
 * 2026-06-04).** Hovering an OUTPUT cell lights up the INPUT cell(s) that feed
 * it, on this same surface — the port-native rebuild of the highlight deleted
 * in the 2.9c-e "honest close". The mapping is pure index math from
 * `src/core/port-provenance.ts` (`lookupProvenance(frame.stepType)`), keyed by
 * `(portName, cellIndex)` so `split-bytes`' multiple output rows stay
 * unambiguous. Only the 10 EXACT port-native primitives highlight; approximate
 * / plumbing primitives (no registered fn) highlight NOTHING — the "missing
 * never wrong" stance. The hover is frame-local, so iterate / `:b{i}` /
 * multi-block "just work" with no per-block logic. MixColumns
 * (`gf-matrix-multiply@1`) renders its GF(2⁸) coefficient as a `×N` badge on
 * each contributor. The byte-format toggle is honored (cells are unreadable
 * without it).
 *
 * **Stale-frame guard = a READ-TIME stepId gate.** `activeSources` recomputes
 * the highlighted set only when `hover().stepId === frame.stepId`; a hover
 * captured on a prior frame paints nothing after a scrub even though the signal
 * still holds its old value. This is deliberately a read-time gate, NOT an
 * effect that clears the signal on frame change — the effect can race the new
 * frame's first paint, the read-time check cannot.
 *
 * **Port-native predicate** (`isPortNativeFrame`): a frame is port-native
 * iff `portInputs !== undefined || portOutputs !== undefined`. Every shipped
 * leaf is port-native (pinned by `tests/requires-ported-dispatch.test.ts`), so
 * `FrameStateView` renders this view unconditionally and the predicate is now
 * informational. Steps that publish only outputs (constants) or only inputs
 * (sinks) still match via the `||`.
 */

import { formatByte } from "@/core/format";
import { type ProvenanceCell, lookupProvenance } from "@/core/port-provenance";
import type { TraceFrame } from "@/core/types";
import { For, Show, createMemo, createSignal } from "solid-js";
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

/** A captured hover: which output cell, on which frame, and the precomputed
 *  input sources that feed it. `stepId` is the gate key (see header). */
type HoverState = {
  readonly stepId: string;
  readonly outPort: string;
  readonly outCellIndex: number;
  readonly sources: readonly ProvenanceCell[];
};

/** Shared empties so the no-port / no-hover branches never allocate — keeps
 *  Solid's reactive equality cheap when scrubbing between empty frames. */
const EMPTY_PORT_ROWS: readonly [string, Uint8Array][] = [];
const EMPTY_PORTS: ReadonlyMap<string, Uint8Array> = new Map();
const EMPTY_SOURCE_MAP: ReadonlyMap<string, string | undefined> = new Map();

/**
 * Cell-strip preview cap (2026-07-12). A port row wider than this collapses to
 * its first `PORT_ROW_CELL_CAP` cells plus an inline expand chip; the full strip
 * shows only when the user opts in.
 *
 * **Why.** A leaf that reads a whole key-derived table on an aux port renders
 * one `.bytes-cell` per byte — Blowfish's `sbox-lookup` reads its 1024-byte
 * S-box, the key-schedule monolith publishes ~4 KB of P+S — so those frames'
 * state view balloons to thousands of px while a neighbouring round frame is
 * ~160 px. Scrubbing onto one shoves everything below it down and yanks the
 * page scroll (the jump the user hit clicking s0..s3). Real operands are ≤ 16
 * bytes and never truncate; only the big lookup tables collapse — which is also
 * the more legible default (the per-frame narration already names the single
 * entry that was read, so a full wall of table hex teaches nothing).
 *
 * The cap is on RENDERED cells only; `bytes.length` (the label count) still
 * reports the true size, and the expand chip reveals every byte on demand. The
 * `expanded` signal is per-`PortRow`; because `<For>` remounts the rows on every
 * frame change (new tuple arrays from the `inputRows`/`outputRows` memos), it
 * resets to collapsed on each scrub — exactly the no-jump default we want.
 */
export const PORT_ROW_CELL_CAP = 32;

export const PortFlowView = (props: Props) => {
  // Materialize port lists once per frame change. Map iteration is
  // insertion order in ES, and the runtime inserts in port-declaration
  // order (see `runtime.ts:502-505`), so the row order matches the
  // executor's contract authoring order — no sort needed.
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

  // ─── Cell-level provenance hover ──────────────────────────────────────────
  const [hover, setHover] = createSignal<HoverState | null>(null);

  // Does this frame's step type have an exact provenance mapping? Drives the
  // "hoverable" affordance on output cells — we only imply interactivity where
  // hovering actually highlights something.
  const hasProvenance = createMemo(() => lookupProvenance(props.frame.stepType) !== undefined);

  // Active highlighted input cells, keyed "portName:cellIndex" → optional GF
  // label. GATED on stepId at READ time (the load-bearing stale-frame guard):
  // a hover captured on a prior frame returns the empty map after a scrub.
  const activeSources = createMemo<ReadonlyMap<string, string | undefined>>(() => {
    const h = hover();
    if (h === null || h.stepId !== props.frame.stepId) return EMPTY_SOURCE_MAP;
    const m = new Map<string, string | undefined>();
    for (const c of h.sources) m.set(`${c.portName}:${c.cellIndex}`, c.label);
    return m;
  });

  // Compute + capture the sources when an output cell is hovered. No fn (an
  // approximate / plumbing primitive) ⇒ clear, so nothing lights up.
  const onOutputEnter = (outPort: string, outCellIndex: number): void => {
    const fn = lookupProvenance(props.frame.stepType);
    if (fn === undefined) {
      setHover(null);
      return;
    }
    const sources = fn({
      params: props.frame.params,
      portInputs: props.frame.portInputs ?? EMPTY_PORTS,
      portOutputs: props.frame.portOutputs ?? EMPTY_PORTS,
      outPort,
      outCellIndex,
    });
    setHover({ stepId: props.frame.stepId, outPort, outCellIndex, sources });
  };
  // Block body required: Solid setters RETURN the value they set, so an
  // expression body would make this `() => HoverState | null`, not `() => void`.
  const onLeave = (): void => {
    setHover(null);
  };

  return (
    <div class="port-flow-view">
      {/* Inputs section. Skipped entirely when there are no input
          ports (e.g. `constant-load@1` — outputs-only). */}
      <Show when={inputRows().length > 0}>
        <div class="port-flow-section" data-section="inputs">
          <For each={inputRows()}>
            {([portName, bytes]) => (
              <PortRow
                side="input"
                portName={portName}
                bytes={bytes}
                activeSources={activeSources}
              />
            )}
          </For>
        </div>
      </Show>

      {/* Separator: rendered only when BOTH sides have ports. */}
      <Show when={inputRows().length > 0 && outputRows().length > 0}>
        <div class="port-flow-divider" aria-hidden="true" />
      </Show>

      {/* Outputs section. Output cells are the hover triggers. */}
      <Show when={outputRows().length > 0}>
        <div class="port-flow-section" data-section="outputs">
          <For each={outputRows()}>
            {([portName, bytes]) => (
              <PortRow
                side="output"
                portName={portName}
                bytes={bytes}
                hoverable={hasProvenance()}
                onCellEnter={onOutputEnter}
                onCellLeave={onLeave}
              />
            )}
          </For>
        </div>
      </Show>
    </div>
  );
};

type PortRowProps = {
  side: "input" | "output";
  portName: string;
  bytes: Uint8Array;
  /** Input side: the active highlighted-source lookup (read inline in the JSX
   *  so the highlight stays reactive to the hover signal). */
  activeSources?: () => ReadonlyMap<string, string | undefined>;
  /** Output side: this frame's step type has a provenance fn (cursor hint). */
  hoverable?: boolean;
  /** Output side: hover handlers carrying (outPort, cellIndex). */
  onCellEnter?: (outPort: string, cellIndex: number) => void;
  onCellLeave?: () => void;
};

/**
 * One labelled row of byte cells for a single port.
 *
 * Cells reuse `.bytes-cell` so visual rhythm matches the step strip. The label
 * sits to the left at fixed width so multi-row stacks align column-wise
 * (operand0 / operand1 / … cells start at the same x). Output cells carry the
 * hover handlers; input cells read `activeSources` to paint `.provenance-source`
 * + a GF `×N` badge. Both the highlight class and `fmt()` are read INLINE in the
 * JSX (not captured in a const) so they stay reactive (Solid `For` rows + the
 * `feedback_solid_conditional_prop_reactivity` rule).
 */
const PortRow = (props: PortRowProps) => {
  const fmt = useByteFormat();
  // Collapsed by default; the row remounts per frame (see PORT_ROW_CELL_CAP),
  // so this resets to collapsed on every scrub — the no-jump default.
  const [expanded, setExpanded] = createSignal(false);
  const allCells = createMemo<readonly { index: number; byte: number }[]>(() => {
    const out: { index: number; byte: number }[] = [];
    for (let i = 0; i < props.bytes.length; i++) {
      out.push({ index: i, byte: props.bytes[i] ?? 0 });
    }
    return out;
  });
  // Whether this row is long enough to collapse, and the cells actually shown.
  const overflows = createMemo(() => props.bytes.length > PORT_ROW_CELL_CAP);
  const cells = createMemo<readonly { index: number; byte: number }[]>(() =>
    overflows() && !expanded() ? allCells().slice(0, PORT_ROW_CELL_CAP) : allCells(),
  );
  const hiddenCount = createMemo(() => props.bytes.length - PORT_ROW_CELL_CAP);
  const toggle = (): void => {
    setExpanded((prev) => !prev);
  };

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
              <div
                class="bytes-cell"
                classList={{
                  "provenance-source":
                    props.side === "input" &&
                    (props.activeSources?.().has(`${props.portName}:${cell.index}`) ?? false),
                  "provenance-hoverable": props.side === "output" && (props.hoverable ?? false),
                }}
                title={`index ${cell.index}`}
                onMouseEnter={
                  props.side === "output"
                    ? () => props.onCellEnter?.(props.portName, cell.index)
                    : undefined
                }
                onMouseLeave={props.side === "output" ? () => props.onCellLeave?.() : undefined}
              >
                {formatByte(cell.byte, fmt())}
                {/* GF coefficient badge (MixColumns). `get` returns the label
                    string for a highlighted source cell, undefined otherwise —
                    so the badge shows only on labelled contributors. */}
                <Show
                  when={
                    props.side === "input"
                      ? props.activeSources?.().get(`${props.portName}:${cell.index}`)
                      : undefined
                  }
                >
                  {(label) => <span class="provenance-label">{label()}</span>}
                </Show>
              </div>
            )}
          </For>
          {/* Expand chip for a collapsed big table (aux lookup tables, published
              key material). Sits inline after the last shown cell; toggles the
              row between the capped preview and the full byte strip. */}
          <Show when={overflows()}>
            <button
              type="button"
              class="port-row-more"
              onClick={toggle}
              title={expanded() ? "show fewer bytes" : "show all bytes"}
            >
              {expanded() ? "show less" : `+${hiddenCount()} more`}
            </button>
          </Show>
        </Show>
      </div>
    </div>
  );
};
