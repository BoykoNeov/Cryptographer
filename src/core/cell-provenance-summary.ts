/**
 * Always-on cell provenance summary — the STATIC counterpart to the hover
 * highlight in `PortFlowView` (leaf-inspector "extended provenance", Tier B,
 * 2026-07-13).
 *
 * **What it does.** Given a port-native `TraceFrame`, it enumerates every output
 * cell's contributing input cells (via the SAME pure index math the hover uses —
 * `lookupProvenance` in `port-provenance.ts`, so there is no second source of
 * truth) and classifies the whole map into one of four shapes so the UI can show
 * the wiring *without* asking the user to hover every cell:
 *
 *   - `"none"` — the step has no exact provenance fn (approximate / plumbing /
 *     no-input primitives), or no output cells. The expander stays hidden — the
 *     "missing never wrong" stance the hover already holds.
 *   - `"same-index"` — every output byte is fed by the SAME-position input
 *     byte(s) on a fixed set of ports (`xor`/`and`/`xor-with-aux`/`not`/
 *     `byte-substitute`). Rendering 16 identical rows would be a wall of noise,
 *     so this collapses to one summary line.
 *   - `"offset"` — every output byte reads a single input byte at a CONSTANT
 *     offset (`byte-slice` — a contiguous window). Also one summary line.
 *   - `"per-cell"` — the map is the point and differs cell to cell: `permute`
 *     (a gather / ShiftRows), `concat`/`split-bytes` (offset boundaries), and
 *     `gf-matrix-multiply` (MixColumns, with GF(2⁸) `×coeff` labels). These
 *     enumerate one row per output cell — exactly where always-on beats hover.
 *
 * **Value-independence (inherited from `port-provenance.ts`).** The classifier
 * reads only port *lengths* and the provenance fn's index output — never a byte
 * *value*. So the summary shape is fixed by the primitive's structure + params,
 * and can't desync onto a per-frame value snapshot. The node tests pin this.
 */

import { type ProvenanceCell, lookupProvenance } from "./port-provenance";
import type { TraceFrame } from "./types";

const EMPTY_PORTS: ReadonlyMap<string, Uint8Array> = new Map();

/** One output cell and the input cells that feed it (the `per-cell` payload). */
export type CellProvenanceRow = {
  readonly outPort: string;
  readonly outIndex: number;
  readonly sources: readonly ProvenanceCell[];
};

/**
 * The classified whole-frame provenance map. `same-index` / `offset` are the
 * collapsed uniform forms; `per-cell` carries the full enumeration; `none`
 * means "show nothing" (no fn or no outputs).
 */
export type CellProvenanceSummary =
  | { readonly kind: "none" }
  | {
      /** Each output byte ← the same-index byte(s) on `ports`. */
      readonly kind: "same-index";
      readonly ports: readonly string[];
      readonly length: number;
    }
  | {
      /** Each output byte ← `port[i + offset]` (a contiguous window). */
      readonly kind: "offset";
      readonly port: string;
      readonly offset: number;
      readonly length: number;
    }
  | { readonly kind: "per-cell"; readonly rows: readonly CellProvenanceRow[] };

/** Ordered port-name equality (the provenance fns emit operands in a stable
 *  `operand0, operand1, …` order every call, so an ordered compare is exact). */
const samePortList = (a: readonly string[], b: readonly string[]): boolean =>
  a.length === b.length && a.every((p, i) => p === b[i]);

/**
 * Collapse a single-output-port map to `same-index` or `offset` when it is
 * uniform, else return null (the caller then renders `per-cell`). A multi-output
 * map (only `split-bytes`) is never collapsed — its per-port offsets ARE the
 * lesson.
 */
const classifyUniform = (rows: readonly CellProvenanceRow[]): CellProvenanceSummary | null => {
  const first = rows[0];
  if (first === undefined) return null;
  // Collapse only single-output-port frames.
  if (rows.some((r) => r.outPort !== first.outPort)) return null;

  // same-index: every cell's sources sit at cellIndex === outIndex, on a
  // consistent (non-empty) port set. Covers xor/and/xor-with-aux/not/substitute.
  const firstPorts = first.sources.map((s) => s.portName);
  const sameIndex = rows.every(
    (r) =>
      r.sources.length > 0 &&
      r.sources.every((s) => s.cellIndex === r.outIndex) &&
      samePortList(
        r.sources.map((s) => s.portName),
        firstPorts,
      ),
  );
  if (sameIndex) return { kind: "same-index", ports: firstPorts, length: rows.length };

  // offset: exactly one source per cell, same port, constant (src − out) ≥ 1.
  // (d === 0 single-source is already caught by same-index above.) Covers
  // byte-slice; a permutation fails the constant-offset check and falls through.
  const s0 = first.sources;
  if (s0.length === 1) {
    const source0 = s0[0];
    if (source0 !== undefined) {
      const port = source0.portName;
      const delta = source0.cellIndex - first.outIndex;
      const uniform = rows.every((r) => {
        const s = r.sources;
        return (
          s.length === 1 &&
          s[0] !== undefined &&
          s[0].portName === port &&
          s[0].cellIndex - r.outIndex === delta
        );
      });
      if (uniform && delta >= 1)
        return { kind: "offset", port, offset: delta, length: rows.length };
    }
  }
  return null;
};

/**
 * Classify a frame's whole cell-provenance map. Pure; safe on any frame — a
 * step with no registered provenance fn (or no output ports) yields `"none"`.
 */
export const summarizeCellProvenance = (frame: TraceFrame): CellProvenanceSummary => {
  const fn = lookupProvenance(frame.stepType);
  if (fn === undefined) return { kind: "none" };
  const outputs = frame.portOutputs;
  if (outputs === undefined || outputs.size === 0) return { kind: "none" };
  const inputs = frame.portInputs ?? EMPTY_PORTS;

  // Gather every (outPort, outIndex) → sources. Map iteration is port-declaration
  // order (runtime insertion order), so rows read in the executor's port order.
  const rows: CellProvenanceRow[] = [];
  for (const [outPort, bytes] of outputs) {
    for (let i = 0; i < bytes.length; i++) {
      const sources = fn({
        params: frame.params,
        portInputs: inputs,
        portOutputs: outputs,
        outPort,
        outCellIndex: i,
      });
      rows.push({ outPort, outIndex: i, sources });
    }
  }
  if (rows.length === 0) return { kind: "none" };

  // A labelled source (a GF(2⁸) coefficient — MixColumns) means the per-cell
  // detail IS the point; never collapse it.
  const anyLabel = rows.some((r) => r.sources.some((s) => s.label !== undefined));
  if (!anyLabel) {
    const uniform = classifyUniform(rows);
    if (uniform !== null) return uniform;
  }
  return { kind: "per-cell", rows };
};
