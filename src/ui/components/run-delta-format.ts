/**
 * Phase 2d — formatter for RunDelta legend strings.
 *
 * Pure function. Lives in its own module (no Solid/DOM imports) so the
 * fast node-env test suite can pin its behavior without spinning up jsdom.
 * Consumed by RunExplorerModal to render the per-tile legend.
 */

import { type ByteFormat, formatByte } from "@/core/format";
import type { RunDelta } from "../stores/history";

const MAX_BYTE_DIFFS_INLINE = 3;
const MAX_PARAM_DIFFS_INLINE = 3;

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

  // Spec parameter changes, grouped by stepId. Most edits touch one step
  // at a time — "round.1.sub-bytes: sbox" reads better than enumerating
  // every (stepId, paramName) pair separately.
  const pc = delta.paramsChanged;
  const grouped = new Map<string, string[]>();
  for (const p of pc) {
    const arr = grouped.get(p.stepId) ?? [];
    arr.push(p.paramName);
    grouped.set(p.stepId, arr);
  }
  const groups = [...grouped.entries()];
  for (const [stepId, names] of groups.slice(0, MAX_PARAM_DIFFS_INLINE)) {
    lines.push(`${stepId}: ${names.join(", ")} changed`);
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
