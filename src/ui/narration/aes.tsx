/**
 * AES round-body narrators — Phase 1 of the per-frame value-prose plan.
 *
 * Four step types, four narrators, all param-driven so forward AND
 * inverse directions are covered by ONE registration per step type
 * (the same trick the provenance fns use at `src/ui/provenance/aes.ts`).
 *
 *   - `generic.byte-substitution@1` → 16 byte units (one per cell).
 *   - `generic.shift-rows@1`        → 4 row units.
 *   - `generic.mix-columns@1`       → 4 column units (per-cell GF(2^8)
 *                                     multiply table inside each).
 *   - `generic.add-round-key@1`     → 16 cell units.
 *
 * Per-unit `<details>` shape (label → body Component) is consistent
 * with `KeyScheduleExplorer`'s per-stage rows so visual rhythm matches
 * across the linear-mode pane.
 *
 * Reactivity: each Prose component is its own `Component<{fmt}>`, so
 * format toggles update byte text inside open disclosures without
 * recreating the `<details>` elements (which would snap them shut).
 * The builder runs once per frame; only `fmt` flows reactively.
 */

import type { Json, MatrixState, TraceFrame } from "@/core/types";
import { For } from "solid-js";
import { formatByteInline, formatBytes } from "../components/byte-row";
import { type NarrationFn, type NarrationUnit, singleAuxNameFromFrame } from "./registry";

// ─── SubBytes ────────────────────────────────────────────────────────

/**
 * Render the 16 S-box lookups that happened in this SubBytes frame.
 * One unit per cell, labelled by linear index AND (row, col) so users
 * can navigate from MatrixView hover to the matching narration unit.
 *
 * Prose body shows the lookup as `S[before] = after`. We don't reach
 * into `params.sbox` to re-verify the table — the executor already
 * computed `after` from `before` via that lookup; trusting the after
 * value avoids an extra source of truth.
 */
export const aesSubBytesNarration: NarrationFn = (frame) => {
  const before = readMatrixBytes(frame.stateBefore);
  const after = readMatrixBytes(frame.stateAfter);
  if (!before || !after) return null;
  const units: NarrationUnit[] = [];
  for (let i = 0; i < 16; i++) {
    const r = i % 4;
    const c = (i - r) / 4;
    const b = before[i] ?? 0;
    const a = after[i] ?? 0;
    units.push({
      key: `byte:${i}`,
      label: `byte ${i} (row ${r}, col ${c})`,
      Prose: (props) => (
        <p>
          S-box lookup at position {i}: S[{formatByteInline(b, props.fmt)}] ={" "}
          {formatByteInline(a, props.fmt)}. Substitution is byte-local — only this cell's value
          changes; (row, col) are preserved.
        </p>
      ),
    });
  }
  return units;
};

// ─── ShiftRows ───────────────────────────────────────────────────────

/**
 * Render the 4 row shifts. Each unit reports the row's before/after
 * byte sequence and the shift amount. Forward AES → `[0, 1, 2, 3]`;
 * inverse → `[0, 3, 2, 1]`. The narrator reads `params.shifts` so
 * one registration covers both directions (and any custom shift
 * table the user types in).
 */
export const aesShiftRowsNarration: NarrationFn = (frame) => {
  const before = readMatrixBytes(frame.stateBefore);
  const after = readMatrixBytes(frame.stateAfter);
  const shifts = readShifts(frame.params);
  if (!before || !after || !shifts) return null;
  const units: NarrationUnit[] = [];
  for (let r = 0; r < 4; r++) {
    const shift = shifts[r] ?? 0;
    const beforeRow = new Uint8Array([
      before[r + 0] ?? 0,
      before[r + 4] ?? 0,
      before[r + 8] ?? 0,
      before[r + 12] ?? 0,
    ]);
    const afterRow = new Uint8Array([
      after[r + 0] ?? 0,
      after[r + 4] ?? 0,
      after[r + 8] ?? 0,
      after[r + 12] ?? 0,
    ]);
    units.push({
      key: `row:${r}`,
      label: `row ${r} (shift = ${shift})`,
      Prose: (props) => (
        <p>
          {shift === 0 ? (
            <>Row {r} is unchanged — shift of 0 leaves all four columns in place.</>
          ) : (
            <>
              Row {r} is rotated left by {shift} column{shift === 1 ? "" : "s"}:{" "}
              {formatBytes(beforeRow, props.fmt)} → {formatBytes(afterRow, props.fmt)}. Byte at
              column 0 moves to column {(4 - shift) % 4}, and so on cyclically.
            </>
          )}
        </p>
      ),
    });
  }
  return units;
};

// ─── MixColumns ──────────────────────────────────────────────────────

/**
 * Render the 4 GF(2^8) matrix multiplies (one per state column). The
 * Prose body shows the 4×4 dot product per output byte, with each
 * contribution rendered as `coeff · source` and the final XOR sum
 * matching the cell's `after` value.
 *
 * Coefficient labels are dropped for `0x01` to keep prose readable
 * (the identity-multiplication contributions render as just the source
 * byte). Zero coefficients are omitted entirely.
 */
export const aesMixColumnsNarration: NarrationFn = (frame) => {
  const before = readMatrixBytes(frame.stateBefore);
  const after = readMatrixBytes(frame.stateAfter);
  const matrix = readMatrix(frame.params);
  if (!before || !after || !matrix) return null;
  const units: NarrationUnit[] = [];
  for (let c = 0; c < 4; c++) {
    const beforeCol = new Uint8Array([
      before[0 + 4 * c] ?? 0,
      before[1 + 4 * c] ?? 0,
      before[2 + 4 * c] ?? 0,
      before[3 + 4 * c] ?? 0,
    ]);
    const afterCol = new Uint8Array([
      after[0 + 4 * c] ?? 0,
      after[1 + 4 * c] ?? 0,
      after[2 + 4 * c] ?? 0,
      after[3 + 4 * c] ?? 0,
    ]);
    units.push({
      key: `col:${c}`,
      label: `column ${c}`,
      Prose: (props) => (
        <div>
          <p>
            Column {c}: {formatBytes(beforeCol, props.fmt)} → {formatBytes(afterCol, props.fmt)}.
            Each output byte is a GF(2^8) dot product of the matrix row with this column.
          </p>
          <ul class="step-narration-mixcol-list">
            <For each={[0, 1, 2, 3]}>
              {(r) => {
                const row = matrix[r] ?? [];
                const terms: string[] = [];
                for (let k = 0; k < 4; k++) {
                  const coeff = row[k] ?? 0;
                  if (coeff === 0) continue;
                  const src = beforeCol[k] ?? 0;
                  const srcStr = formatByteInline(src, props.fmt);
                  terms.push(
                    coeff === 1 ? srcStr : `0x${coeff.toString(16).padStart(2, "0")}·${srcStr}`,
                  );
                }
                const sum = afterCol[r] ?? 0;
                return (
                  <li>
                    row {r}: {terms.join(" ⊕ ") || "0"} = {formatByteInline(sum, props.fmt)}
                  </li>
                );
              }}
            </For>
          </ul>
        </div>
      ),
    });
  }
  return units;
};

// ─── AddRoundKey ─────────────────────────────────────────────────────

/**
 * Render the 16 XORs. Each unit reports `before[i] ⊕ K[i] = after[i]`
 * with the K identifying its aux name (e.g. `roundKey.3`). Reads the
 * consumed aux from `frame.auxRead` rather than `params.auxName` so
 * the narration matches what the runtime actually consumed.
 *
 * If the aux is missing or wrong-shape (defensive — shouldn't happen
 * for a frame that landed in the trace), return null and let the
 * component render nothing for that frame.
 */
export const aesAddRoundKeyNarration: NarrationFn = (frame) => {
  const before = readMatrixBytes(frame.stateBefore);
  const after = readMatrixBytes(frame.stateAfter);
  if (!before || !after) return null;
  const auxName = singleAuxNameFromFrame(frame);
  if (auxName === null) return null;
  const auxValue = frame.auxRead.get(auxName);
  if (!(auxValue instanceof Uint8Array) || auxValue.length < 16) return null;
  const units: NarrationUnit[] = [];
  for (let i = 0; i < 16; i++) {
    const r = i % 4;
    const c = (i - r) / 4;
    const b = before[i] ?? 0;
    const k = auxValue[i] ?? 0;
    const a = after[i] ?? 0;
    units.push({
      key: `cell:${i}`,
      label: `cell ${i} (row ${r}, col ${c})`,
      Prose: (props) => (
        <p>
          {formatByteInline(b, props.fmt)} ⊕ {auxName}[{i}] = {formatByteInline(k, props.fmt)} ={" "}
          {formatByteInline(a, props.fmt)}. XOR is self-inverse — applying the same key bit twice
          cancels.
        </p>
      ),
    });
  }
  return units;
};

// ─── Helpers ─────────────────────────────────────────────────────────

const readMatrixBytes = (state: TraceFrame["stateBefore"] | null): Uint8Array | null => {
  if (!state) return null;
  if (state.shape !== "matrix4x4-bytes") return null;
  return (state as MatrixState).bytes;
};

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

// Export shared param-readers for re-use by other narrators in future
// phases (e.g. a Serpent-specific module wants the same shift / matrix
// validation patterns; until then keep them module-local).
