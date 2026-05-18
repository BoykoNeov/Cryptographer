/**
 * AES per-step provenance functions. Phase 3 of the linear-mode pedagogy
 * plan. Covers the four AES round operations:
 *
 *   - `generic.byte-substitution@1` (SubBytes) — same-position S-box lookup.
 *   - `generic.shift-rows@1` (ShiftRows) — shifted-position byte from the
 *     same row. Reads `params.shifts: number[4]` so forward `[0,1,2,3]`
 *     and inverse `[0,3,2,1]` are both covered by ONE provenance fn.
 *   - `generic.mix-columns@1` (MixColumns) — four same-column cells with
 *     their GF(2^8) coefficients annotated. Reads `params.matrix` so
 *     forward `{02,03,01,01}` and inverse `{0e,0b,0d,09}` are both
 *     covered by ONE provenance fn.
 *   - `generic.add-round-key@1` (AddRoundKey) — same-position XOR with
 *     the consumed `roundKey.N` aux. Returns BOTH a before-cell AND an
 *     aux-cell source so the RoundKeyPanel highlights match.
 *
 * The param-driven design means I don't need separate forward/inverse
 * registrations — the same fn handles both directions because the
 * generic.* step types are also direction-agnostic (the direction lives
 * in the `params.shifts` / `params.matrix` value, not the step type
 * name). Decrypt-mode hover lights up the correctly-shifted source
 * cells "for free" via the params lookup.
 */

import type { Json } from "@/core/types";
import { type ProvenanceFn, type ProvenanceSource, singleAuxNameFromFrame } from "./registry";

/**
 * SubBytes — `after[i] = S-box[before[i]]`. Same position; one source
 * per output cell. The S-box lookup value isn't surfaced as a label
 * here (the user can see the byte difference in the cells themselves).
 *
 * `frame.params.sbox` MIGHT carry a non-canonical S-box (the user can
 * edit it), but the provenance contract is the position relation,
 * not the byte values, so we don't need to read the table.
 */
export const aesSubBytesProvenance: ProvenanceFn = (_frame, afterCellIndex) => {
  if (afterCellIndex < 0 || afterCellIndex >= 16) return [];
  return [{ kind: "before-cell", index: afterCellIndex }];
};

/**
 * ShiftRows — `after[r + 4c] = before[r + 4·((c + shifts[r]) mod 4)]`.
 * One source per output cell. The shifts array is param-driven, so the
 * fn covers forward `[0,1,2,3]` and inverse `[0,3,2,1]` (and any
 * user-customized shift table) without separate registrations.
 */
export const aesShiftRowsProvenance: ProvenanceFn = (frame, afterCellIndex) => {
  if (afterCellIndex < 0 || afterCellIndex >= 16) return [];
  const shifts = readShifts(frame.params);
  if (!shifts) return [];
  // Decompose linear index back to (row, col) under column-major storage.
  const r = afterCellIndex % 4;
  const c = (afterCellIndex - r) / 4;
  const srcCol = (c + (shifts[r] ?? 0)) % 4;
  const srcIndex = r + 4 * srcCol;
  return [{ kind: "before-cell", index: srcIndex }];
};

/**
 * MixColumns — `after[r + 4c] = ⊕ over k in 0..3 of matrix[r][k] · before[k + 4c]`.
 * Four sources per output cell (same column, all four rows), each labelled
 * with its GF(2^8) coefficient as a hex string ("0x02", "0x0e", …) so the
 * UI can render the coefficient in a tooltip without re-parsing params.
 * Coefficient labels are dropped for `0x01` (multiplicative identity —
 * the byte passes through unchanged; including the "× 0x01" annotation
 * is visual noise).
 */
export const aesMixColumnsProvenance: ProvenanceFn = (frame, afterCellIndex) => {
  if (afterCellIndex < 0 || afterCellIndex >= 16) return [];
  const matrix = readMatrix(frame.params);
  if (!matrix) return [];
  const r = afterCellIndex % 4;
  const c = (afterCellIndex - r) / 4;
  const row = matrix[r];
  if (!row) return [];
  const out: ProvenanceSource[] = [];
  for (let k = 0; k < 4; k++) {
    const coeff = row[k] ?? 0;
    if (coeff === 0) continue; // a zero coefficient contributes nothing
    const srcIndex = k + 4 * c;
    // Spread the label key in only when defined — exactOptionalPropertyTypes
    // disallows `{ label: undefined }` even though `label?: string` accepts
    // a missing key. The 1-coefficient (identity multiplication) case has
    // no visual annotation, so we omit the label rather than render "× 1".
    if (coeff === 1) {
      out.push({ kind: "before-cell", index: srcIndex });
    } else {
      out.push({
        kind: "before-cell",
        index: srcIndex,
        label: `× 0x${coeff.toString(16).padStart(2, "0")}`,
      });
    }
  }
  return out;
};

/**
 * AddRoundKey — `after[i] = before[i] ⊕ roundKey[i]`. TWO sources per
 * output cell: the same-position before cell AND the same-position cell
 * in the consumed round-key aux. The latter lights up the corresponding
 * cell in the RoundKeyPanel.
 *
 * Aux name comes from `frame.auxRead` rather than `frame.params.auxName`
 * because the executor's auxRead snapshot IS what landed in the trace —
 * if a future step type with multiple aux reads needs more sophisticated
 * source picking, it can override; for AddRoundKey there's always
 * exactly one aux consumed.
 */
export const aesAddRoundKeyProvenance: ProvenanceFn = (frame, afterCellIndex) => {
  if (afterCellIndex < 0 || afterCellIndex >= 16) return [];
  const sources: ProvenanceSource[] = [{ kind: "before-cell", index: afterCellIndex }];
  const auxName = singleAuxNameFromFrame(frame);
  if (auxName !== null) {
    const auxValue = frame.auxRead.get(auxName);
    if (auxValue instanceof Uint8Array && afterCellIndex < auxValue.length) {
      sources.push({ kind: "aux-cell", auxName, index: afterCellIndex });
    }
  }
  return sources;
};

// ─── Param readers ──────────────────────────────────────────────────

const readShifts = (params: Json): readonly number[] | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const v = (params as Record<string, Json>).shifts;
  if (!Array.isArray(v) || v.length !== 4) return null;
  if (!v.every((n) => typeof n === "number")) return null;
  return v as readonly number[];
};

const readMatrix = (params: Json): readonly (readonly number[])[] | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const m = (params as Record<string, Json>).matrix;
  if (!Array.isArray(m) || m.length !== 4) return null;
  for (const row of m) {
    if (!Array.isArray(row) || row.length !== 4) return null;
    if (!row.every((n) => typeof n === "number")) return null;
  }
  return m as readonly (readonly number[])[];
};
