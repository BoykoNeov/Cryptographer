/**
 * DES per-step provenance functions. Phase 4 of `docs/plans/des-feistel.md`.
 *
 * Covers the 6 DES step types whose `shapeContract.input` is `"bytes"`:
 *
 *   - `des.initial-permutation@1` / `des.final-permutation@1` /
 *     `des.expand-R@1` / `des.p-permutation@1` — bit permutations.
 *     Output byte j is fed by the deduplicated set of input bytes whose
 *     bits feed any of byte j's output bits per the FIPS table.
 *   - `des.xor-with-K@1` — cell-wise XOR. Output byte i ← input byte i
 *     AND `aux[roundKey.N][i]`.
 *   - `des.s-boxes@1` — output byte j packs two S-box outputs (S_{2j+1}
 *     in the high nibble, S_{2j+2} in the low). Each S-box reads 6
 *     input bits, so the output byte's deduplicated input-byte set is
 *     the union of those bits' parent bytes.
 *
 * **Honest byte-level provenance.** Unlike Serpent's bit-permutation
 * (where every output bit derives from one input bit but the byte-level
 * union would still be misleading because Serpent's table scatters
 * widely), DES's permutations stay relatively local — IP / FP move bits
 * across the 8 bytes in a structured pattern, and the F-function's
 * sub-tables read narrow source ranges. The byte-level highlight reads
 * as "these specific input bytes touched this output byte," which is
 * informative without the GF(2) ambiguity that keeps Serpent's linear
 * transforms on the allowlist.
 *
 * **Bit numbering: FIPS 46-3 convention.** Tables are 1-indexed and
 * MSB-first within each byte. The provenance fn translates from FIPS
 * bit positions back to 0-indexed byte indices for the UI's
 * `before-cell` source kind.
 */

import type { Json } from "@/core/types";
import { type ProvenanceFn, type ProvenanceSource, singleAuxNameFromFrame } from "./registry";

// ─── Bit-permutation provenance (shared by IP / FP / E / P) ────────────

/**
 * Build a provenance fn for a fixed-length bit-permutation step. The
 * `inLen` / `outLen` are in BYTES (not bits) and `outBits` is the
 * meaningful output-bit count (8 × outLen for fully-packed buffers; the
 * trailing partial byte in a non-byte-aligned table — none today — gets
 * fewer bits).
 *
 * Returns a function that maps `afterCellIndex` (0..outLen-1) to the
 * deduplicated set of input bytes whose bits contribute to that output
 * byte. Empty array for out-of-range indices.
 */
const makeBitPermutationProvenance = (
  inLen: number,
  outLen: number,
  outBits: number,
): ProvenanceFn => {
  return (frame, afterCellIndex) => {
    if (afterCellIndex < 0 || afterCellIndex >= outLen) return [];
    const table = readTable(frame.params, outBits);
    if (!table) return [];
    const bitsInThisByte = Math.min(8, outBits - 8 * afterCellIndex);
    const seen = new Set<number>();
    const sources: ProvenanceSource[] = [];
    for (let p = 0; p < bitsInThisByte; p++) {
      const fipsOutputBit = 8 * afterCellIndex + p + 1; // 1-indexed
      const srcFipsBit = table[fipsOutputBit - 1] ?? 0;
      if (srcFipsBit < 1 || srcFipsBit > 8 * inLen) continue;
      const srcByteIndex = (srcFipsBit - 1) >> 3;
      if (seen.has(srcByteIndex)) continue;
      seen.add(srcByteIndex);
      sources.push({ kind: "before-cell", index: srcByteIndex });
    }
    return sources;
  };
};

export const desInitialPermutationProvenance: ProvenanceFn = makeBitPermutationProvenance(8, 8, 64);
export const desFinalPermutationProvenance: ProvenanceFn = makeBitPermutationProvenance(8, 8, 64);
export const desExpandRProvenance: ProvenanceFn = makeBitPermutationProvenance(4, 6, 48);
export const desPPermutationProvenance: ProvenanceFn = makeBitPermutationProvenance(4, 4, 32);

// ─── xor-with-K ────────────────────────────────────────────────────────

/**
 * `after[i] = before[i] ⊕ aux[roundKey.N][i]`. Same-position before-cell
 * + same-position aux-cell, matching `aesAddRoundKeyProvenance` shape so
 * the UI's existing hover machinery picks it up uniformly.
 */
export const desXorWithKProvenance: ProvenanceFn = (frame, afterCellIndex) => {
  if (afterCellIndex < 0 || afterCellIndex >= 6) return [];
  const sources: ProvenanceSource[] = [{ kind: "before-cell", index: afterCellIndex }];
  const auxName = singleAuxNameFromFrame(frame);
  if (auxName !== null) {
    sources.push({
      kind: "aux-cell",
      auxName,
      index: afterCellIndex,
      label: `K[${afterCellIndex}]`,
    });
  }
  return sources;
};

// ─── S-boxes ────────────────────────────────────────────────────────────

/**
 * `des.s-boxes@1` output layout (FIPS 46-3 Appendix A):
 *
 *   - 8 S-boxes (S1..S8) run in parallel.
 *   - S_n consumes input FIPS bits `6(n-1)+1..6n` (6 input bits each).
 *   - S_n produces 4 output bits, written MSB-first into FIPS output bits
 *     `4(n-1)+1..4n`. So S_n's nibble lands at byte `(n-1) >> 1`, position
 *     "high" (`(n-1) & 1 === 0`) or "low" (`(n-1) & 1 === 1`).
 *
 * Output byte j ∈ 0..3 receives nibbles from S_{2j+1} (high) and
 * S_{2j+2} (low). Each S-box's 6 input bits map back to a small set of
 * input bytes via `(fipsBit-1) >> 3`.
 *
 * Implementation: the FIPS S-box positions are static — no params to
 * read for the position mapping (the `params.sboxes` table values affect
 * the OUTPUT values but not the bit-positions). So the provenance fn
 * doesn't read frame params at all.
 */
export const desSBoxesProvenance: ProvenanceFn = (_frame, afterCellIndex) => {
  if (afterCellIndex < 0 || afterCellIndex >= 4) return [];
  // The two S-boxes feeding this output byte (1-indexed S_n labels: S_{2j+1}, S_{2j+2}).
  const sboxLowIndex = 2 * afterCellIndex; // 0-indexed: S_{2j+1}
  const sboxHighIndex = 2 * afterCellIndex + 1; // 0-indexed: S_{2j+2}
  const seen = new Set<number>();
  const sources: ProvenanceSource[] = [];
  for (const sboxIdx of [sboxLowIndex, sboxHighIndex]) {
    // S_n (1-indexed) reads FIPS bits 6(n-1)+1..6n. In 0-indexed
    // terms: bits 6 * sboxIdx..6 * sboxIdx + 5.
    for (let p = 0; p < 6; p++) {
      const fipsBit = 6 * sboxIdx + p + 1;
      const srcByteIndex = (fipsBit - 1) >> 3;
      if (seen.has(srcByteIndex)) continue;
      seen.add(srcByteIndex);
      sources.push({
        kind: "before-cell",
        index: srcByteIndex,
        label: `S${sboxIdx + 1}`,
      });
    }
  }
  return sources;
};

// ─── Helpers ───────────────────────────────────────────────────────────

const readTable = (params: Json, expectedLength: number): readonly number[] | null => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) return null;
  const t = (params as Record<string, Json>).table;
  if (!Array.isArray(t) || t.length !== expectedLength) return null;
  if (!t.every((n) => typeof n === "number")) return null;
  return t as readonly number[];
};
