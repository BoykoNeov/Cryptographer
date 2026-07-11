/**
 * DES key-schedule bit permutation — port-native generic FIPS bit-permute
 * primitive (key-schedule-decomposition slice K4a, 2026-06-02).
 *
 * `output_bit[i] = input_bit[table[i-1]]` for i in 1..outBits, FIPS 46-3
 * bit numbering (1-indexed, MSB-first). A verbatim lift of `fipsPermute`
 * (the same helper the monolithic `des.key-schedule@1` used) so the
 * decomposed schedule's PC-1 / PC-2 frames are byte-identical to the
 * monolith by construction.
 *
 * **Why a NEW generic step, not `permute@1`.** `permute@1` gathers whole
 * BYTES (`output[i] = input[indices[i]]`); PC-1 (64→56) and PC-2 (56→48)
 * are BIT permutations that also change the bit-length and cross byte
 * boundaries. None of the byte-granular port-native primitives can express
 * them, so the DES schedule needs a bit-level permute.
 *
 * **Why not reuse `des.p-permutation@1` etc.** The round-body permutes
 * (IP/FP/E/P) are role-specific with hardcoded I/O bit widths (64→64,
 * 32→48, 32→32) and a `state` port. PC-1/PC-2 have their own widths
 * (64→56, 56→48). A single generic `des.bit-permute@1` parameterized by
 * `table` + `outBits` serves both. The name is `bit-permute` (not
 * `key-permute`) deliberately: it leaves the door open to later absorbing
 * the role-specific round-body permutes into this one type — but that
 * refactor is out of scope here (K4a is producer-only decomposition).
 *
 * Port-native: `kind:"ported"`, one raw `input` port, one raw `output`
 * port, no `meta`, no `shapeContract`. The output byteLength is
 * `ceil(outBits / 8)` but left polymorphic on the contract (resolved by
 * the wired `outBits`), matching the `permute@1` posture.
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { fipsPermute } from "./des-bit-ops";

type Params = {
  readonly table: readonly number[];
  readonly outBits: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.bit-permute: params must be an object");
  }
  const p = params as { table?: unknown; outBits?: unknown };
  if (typeof p.outBits !== "number" || !Number.isInteger(p.outBits) || p.outBits < 1) {
    throw new Error("des.bit-permute: params.outBits must be a positive integer");
  }
  if (!Array.isArray(p.table) || p.table.length !== p.outBits) {
    throw new Error(
      `des.bit-permute: params.table must be an array of exactly outBits (${p.outBits}) FIPS 1-indexed source-bit positions`,
    );
  }
  for (const idx of p.table) {
    if (typeof idx !== "number" || !Number.isInteger(idx) || idx < 1) {
      throw new Error(
        "des.bit-permute: every table entry must be a positive integer (FIPS 1-indexed)",
      );
    }
  }
  return { table: p.table as readonly number[], outBits: p.outBits };
};

/**
 * Read the bit-buffer off the `input` port and apply the FIPS permutation.
 * `fipsPermute` tolerates out-of-range source indices (returns 0), but the
 * PC-1 / PC-2 tables only ever reference valid bits of their fixed-width
 * input, so a wrong-length input surfaces as a wrong round key in the KAT,
 * not a silent truncation.
 */
export const desBitPermute: PortedExecutor = (inputs, params, _ctx) => {
  const { table, outBits } = readParams(params);
  const input = inputs.get("input");
  if (!(input instanceof Uint8Array)) {
    throw new Error("des.bit-permute: input port 'input' must carry a byte buffer");
  }
  return new Map([["output", fipsPermute(input, table, outBits)]]);
};

// ─── Port contract ──────────────────────────────────────────────────────────
// Static raw maps; output byteLength polymorphic (= ceil(outBits/8), resolved
// by the wired param). Same posture as `permute@1`.

export const desBitPermutePortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw" }]]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const desBitPermuteDoc: StepDocumentation = {
  name: "Bit Permutation (DES key schedule)",
  summary: "FIPS bit permutation: output_bit[i] = input_bit[table[i]]. Used for PC-1 and PC-2.",
  detail: `## Bit Permutation (DES key schedule)

A bit-level permutation under FIPS 46-3 numbering (1-indexed, MSB-first):

\`\`\`
output_bit[i] = input_bit[table[i - 1]]      for i in 1..outBits
\`\`\`

Unlike a byte-level permutation, this works one bit at a time and can change
the total number of bits (PC-1 drops 8 bits; PC-2 drops 8 more).

**Where it fits in the DES key schedule.**

- **PC-1** (Permuted Choice 1, 64 → 56): drops the 8 parity bits (key
  positions 8, 16, …, 64 — never referenced by the table) and reorders the
  surviving 56 bits into C₀ ‖ D₀.
- **PC-2** (Permuted Choice 2, 56 → 48): after each round's left-rotation
  of the C / D halves, selects 48 of the 56 bits as that round's key Kᵣ.

Both are pure bit-wiring — the entire DES key schedule contains no
arithmetic, only this permute and the per-round rotation.`,
  params: new Map([
    [
      "table",
      "For each output bit, which input bit it comes from — the PC-1 table (56 entries) or the PC-2 table (48 entries).",
    ],
    ["outBits", "How many output bits: 56 for PC-1, 48 for PC-2."],
  ]),
  references: ["FIPS 46-3 §5 (Key Schedule — Tables PC-1, PC-2)"],
  // No shapeContract — port-native steps describe their surface via the
  // PortContract. (Stays off the narration cell-shape coverage gate.)
};
