/**
 * Phase 2d — formatter for RunDelta legend strings.
 *
 * Pure function. Lives in its own module (no Solid/DOM imports) so the
 * fast node-env test suite can pin its behavior without spinning up jsdom.
 * Consumed by RunExplorerModal to render the per-tile legend.
 *
 * Phase 2d+ (May 2026) extension: when `SpecParamDiff` carries scalar or
 * per-cell value info, we render that directly ("S-box[row 0, col 0]
 * 63 → 00" / "rounds 10 → 12") instead of the older "X changed" summary.
 * The summary is still used as a fallback for diffs we couldn't classify
 * (nested objects, mixed-shape changes), so the test that pins the
 * pre-extension wording continues to pass for bare diffs.
 */

import { type ByteFormat, formatByte } from "@/core/format";
import type { ParamCellDiff, SpecParamDiff } from "@/core/spec-mutations";
import type { Json } from "@/core/types";
import type { RunDelta } from "../stores/history";

const MAX_BYTE_DIFFS_INLINE = 3;
const MAX_PARAM_DIFFS_INLINE = 3;
// Per-param cap on per-cell lines: bumped from 3 to 8 (May 2026) so editing
// a whole row of the S-box (16 cells) doesn't collapse to "…and 13 more"
// immediately. Past 8 we still summarize to avoid blowing up the legend
// when someone resets the whole table.
const MAX_PARAM_CELLS_INLINE = 8;

/**
 * Render a RunDelta as a list of short human-readable lines. The active
 * byte format threads through so the legend matches the values the user
 * sees in the matrix tiles (e.g. "00 → 10" in hex vs. "0 → 16" in decimal).
 *
 * Capped at MAX_*_INLINE entries per category so a wildly different run
 * doesn't take over the legend — overflow collapses to a "…and N more"
 * line. Param changes group by stepId so editing several keys on the same
 * step renders as one comma-joined line.
 */
export const describeDelta = (delta: RunDelta | null, fmt: ByteFormat): readonly string[] => {
  if (delta === null) return ["(baseline run — nothing to compare against yet)"];

  const lines: string[] = [];

  // Plaintext / ciphertext byte changes.
  const ic = delta.inputChanged;
  for (const d of ic.slice(0, MAX_BYTE_DIFFS_INLINE)) {
    lines.push(`input byte ${d.index}: ${formatByte(d.from, fmt)} → ${formatByte(d.to, fmt)}`);
  }
  if (ic.length > MAX_BYTE_DIFFS_INLINE) {
    lines.push(`…and ${ic.length - MAX_BYTE_DIFFS_INLINE} more input byte(s)`);
  }

  // Key byte changes — distinct prefix so the user can tell which buffer
  // the diff lives on.
  const kc = delta.keyChanged;
  for (const d of kc.slice(0, MAX_BYTE_DIFFS_INLINE)) {
    lines.push(`key byte ${d.index}: ${formatByte(d.from, fmt)} → ${formatByte(d.to, fmt)}`);
  }
  if (kc.length > MAX_BYTE_DIFFS_INLINE) {
    lines.push(`…and ${kc.length - MAX_BYTE_DIFFS_INLINE} more key byte(s)`);
  }

  // Spec parameter changes, grouped by stepId. Most edits touch one step at
  // a time — emitting one block per stepId reads better than enumerating
  // every (stepId, paramName) pair separately. Inside each step's block:
  // diffs with value info get a detailed line (or per-cell lines for array
  // params); bare diffs fall back to the legacy comma-joined "X changed"
  // summary.
  const pc = delta.paramsChanged;
  const grouped = new Map<string, SpecParamDiff[]>();
  for (const p of pc) {
    const arr = grouped.get(p.stepId) ?? [];
    arr.push(p);
    grouped.set(p.stepId, arr);
  }
  const groups = [...grouped.entries()];
  for (const [stepId, diffs] of groups.slice(0, MAX_PARAM_DIFFS_INLINE)) {
    appendStepDiffLines(lines, stepId, diffs, fmt);
  }
  if (groups.length > MAX_PARAM_DIFFS_INLINE) {
    lines.push(`…and ${groups.length - MAX_PARAM_DIFFS_INLINE} more step(s) edited`);
  }

  if (lines.length === 0) {
    // Should be impossible since pushSnapshot dedups exact duplicates, but
    // guard against future code paths that might insert a no-delta entry.
    lines.push("(no observable change)");
  }
  return lines;
};

/**
 * Emit the lines for one stepId's diff bucket. Splits the bucket into two
 * categories — value-detailed (scalar or per-cell) and bare ("just
 * changed") — so we can render the detailed ones individually while
 * still collapsing bare diffs into a single comma-joined summary line.
 */
const appendStepDiffLines = (
  out: string[],
  stepId: string,
  diffs: readonly SpecParamDiff[],
  fmt: ByteFormat,
): void => {
  const bareNames: string[] = [];

  for (const d of diffs) {
    if (d.scalar !== undefined) {
      out.push(
        `${stepId}: ${d.paramName} ${renderScalar(d.scalar.from)} → ${renderScalar(d.scalar.to)}`,
      );
      continue;
    }
    if (d.cells !== undefined && d.cells.length > 0) {
      const shown = d.cells.slice(0, MAX_PARAM_CELLS_INLINE);
      for (const cell of shown) {
        out.push(`${stepId}: ${formatCellLabel(d.paramName, cell)} ${renderCellValues(cell, fmt)}`);
      }
      if (d.cells.length > MAX_PARAM_CELLS_INLINE) {
        out.push(
          `${stepId}: …and ${d.cells.length - MAX_PARAM_CELLS_INLINE} more ${d.paramName} cell(s)`,
        );
      }
      continue;
    }
    // Bare diff: param differs but we couldn't classify it (nested object,
    // mixed shape, "(type)" / "(structure)" markers). Group these.
    bareNames.push(d.paramName);
  }

  if (bareNames.length > 0) {
    out.push(`${stepId}: ${bareNames.join(", ")} changed`);
  }
};

/**
 * Build the "address" label for a cell diff. For 1D arrays we just show the
 * flat index (`shifts[3]`); for 2D we show coordinates in hex so a 16×16
 * S-box edit reads naturally as `sbox[row 0, col f]`. Hex matches the
 * SboxEditor's axis labels — single-digit max for the 4×4 MixColumns
 * matrix (where 0..3 looks the same in hex/decimal) and at most one hex
 * char for 16×16 tables.
 */
const formatCellLabel = (paramName: string, cell: ParamCellDiff): string => {
  if (cell.kind === "2d") {
    return `${paramName}[row ${cell.row.toString(16)}, col ${cell.col.toString(16)}]`;
  }
  return `${paramName}[${cell.index}]`;
};

/** Format the from/to byte values of a cell diff using the active ByteFormat. */
const renderCellValues = (cell: ParamCellDiff, fmt: ByteFormat): string =>
  `${formatByte(cell.from, fmt)} → ${formatByte(cell.to, fmt)}`;

/**
 * Stringify a JSON scalar for the legend. Strings get quoted so the user
 * can tell `"10"` (string) from `10` (number); other scalars fall through
 * to `String(v)`. Note: scalar-typed param values are typically counts
 * (`rounds`), names (`auxName`), or flags — not byte values — so we
 * deliberately avoid `formatByte` here. A byte-shaped scalar like `0x10`
 * still renders as `16` in decimal mode, which is consistent with the
 * "this is just a number" mental model for scalars.
 */
const renderScalar = (v: Json): string => {
  if (typeof v === "string") return `"${v}"`;
  return String(v);
};
