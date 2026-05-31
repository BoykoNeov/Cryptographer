/**
 * Serpent per-step provenance functions. Phase 3 of the pedagogy plan.
 *
 * Covered:
 *   - `serpent.add-round-key@1` — XOR with `roundKey.N` aux, byte-wise.
 *     Same shape as AES AddRoundKey (same-position before-cell + aux-cell
 *     source).
 *   - `serpent.sub-bytes@1` — same-position 4-bit S-box lookup applied to
 *     each nibble of each byte. Both nibbles of `after[i]` derive from
 *     the same byte `before[i]`, so the provenance is a single same-
 *     position source — identical to AES SubBytes.
 *
 * NOT covered (intentionally — on the registry's no-provenance allowlist):
 *   - `serpent.linear-transform@1` / `inv-linear-transform@1` — bit-level
 *     XOR mixing. Each output bit derives from 6–7 input bits; a byte-
 *     level approximation would highlight nearly every input byte and
 *     read as "everything contributes to everything" — uninformative.
 *   - `serpent.bit-permutation@1` (IP/FP) — bit-level shuffle, same issue.
 */

import { frameStateOutBytes } from "@/core/frame-state";
import type { TraceFrame } from "@/core/types";
import { type ProvenanceFn, type ProvenanceSource, singleAuxNameFromFrame } from "./registry";

/**
 * Serpent AddRoundKey — same shape as AES's: `after[i] = before[i] ⊕ K[i]`,
 * byte-wise, for i in 0..15. State is BytesState (16-byte buffer) rather
 * than MatrixState, but the per-byte mapping is identical.
 */
export const serpentAddRoundKeyProvenance: ProvenanceFn = (frame, afterCellIndex) => {
  if (afterCellIndex < 0) return [];
  // Defensive: Serpent state is always 16 bytes when AddRoundKey runs;
  // the upper guard catches accidental over-indexing without throwing.
  // The `"state"` output port (the `stateAfter` State field fallback retired
  // in Slice 5.3e Batch 4 → null if the leaf has no `"state"` port; the upper
  // bound guard below only fires when a port is present).
  const after = frameStateOutBytes(frame);
  if (after !== null && afterCellIndex >= after.length) {
    return [];
  }
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

/**
 * Serpent SubBytes — 4-bit S-box applied to each nibble in standard form.
 * The output byte at position `i` is `(S[high(before[i])] << 4) |
 * S[low(before[i])]`, where the S-box selection rotates through the
 * 8 Serpent S-boxes by round (per the `sboxIndex` param). The user-
 * facing provenance is byte-level: same position, same byte.
 *
 * Nibble-level provenance is conceivable (high nibble of `after[i]`
 * derives only from high nibble of `before[i]`, etc.) but Phase 3
 * targets cell-level highlights, and our cells are bytes — not nibbles.
 * If a future "nibble inspector" lands it can layer on a finer
 * provenance variant.
 */
export const serpentSubBytesProvenance: ProvenanceFn = (frame: TraceFrame, afterCellIndex) => {
  if (afterCellIndex < 0) return [];
  // Port-first read (Slice 5.3c) — see `serpentAddRoundKeyProvenance` above.
  const after = frameStateOutBytes(frame);
  if (after !== null && afterCellIndex >= after.length) {
    return [];
  }
  return [{ kind: "before-cell", index: afterCellIndex }];
};
