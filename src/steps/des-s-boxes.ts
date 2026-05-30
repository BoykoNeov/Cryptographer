/**
 * DES S-boxes. FIPS 46-3 Appendix A.
 *
 * The cipher's only nonlinear component. Reads a 48-bit input as 8 groups
 * of 6 bits, looks each group up in one of 8 distinct 6→4 substitution
 * tables (S1..S8), and concatenates the eight 4-bit outputs into a 32-bit
 * value.
 *
 * For each 6-bit group b1 b2 b3 b4 b5 b6:
 *   - **row** = `(b1 << 1) | b6`   (outer two bits, 0..3)
 *   - **col** = `(b2 << 3) | (b3 << 2) | (b4 << 1) | b5`   (inner four, 0..15)
 *
 * The 4-bit S-box output is written MSB-first into the corresponding
 * 4-bit slot of the output buffer.
 *
 * **Shape transition.** Input is 6 bytes (48 bits); output is 4 bytes
 * (32 bits). This is the second of two shape-changing steps inside F
 * (the first is `des.expand-R@1`'s 4→6 byte expansion).
 *
 * Params: `{ sboxes: number[8][4][16] }`. Standard `DES_SBOXES` lives in
 * `src/ciphers/des-constants.ts`.
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { bitsToFipsBytes, fipsBytesToBits } from "./des-bit-ops";

/**
 * Port-native since B4 (universal-port Phase 4d DES rebuild). Reads the
 * 6-byte (48-bit) E⊕K_i value from the `state` input port and emits the
 * 4-byte (32-bit) substituted result on the `state` output port. No aux.
 */
export const desSBoxes: PortedExecutor = (inputs, params) => {
  const bytes = inputs.get("state");
  if (bytes === undefined) {
    throw new Error("des.s-boxes: missing required input port 'state'");
  }
  if (bytes.length !== 6) {
    throw new Error(`des.s-boxes expects 6-byte (48-bit) state; got ${bytes.length}`);
  }
  const sboxes = readSBoxes(params);
  const inBits = fipsBytesToBits(bytes, 48);
  const outBits = new Array<number>(32);
  for (let s = 0; s < 8; s++) {
    // 6 bits b1..b6 = inBits[s*6 .. s*6+5]
    const b1 = inBits[s * 6 + 0] ?? 0;
    const b2 = inBits[s * 6 + 1] ?? 0;
    const b3 = inBits[s * 6 + 2] ?? 0;
    const b4 = inBits[s * 6 + 3] ?? 0;
    const b5 = inBits[s * 6 + 4] ?? 0;
    const b6 = inBits[s * 6 + 5] ?? 0;
    const row = (b1 << 1) | b6;
    const col = (b2 << 3) | (b3 << 2) | (b4 << 1) | b5;
    const box = sboxes[s];
    if (!box) throw new Error(`des.s-boxes: missing S-box ${s + 1}`);
    const rowArr = box[row];
    if (!rowArr) throw new Error(`des.s-boxes: missing row ${row} of S-box ${s + 1}`);
    const val = rowArr[col] ?? 0;
    // Write 4-bit val MSB-first into outBits[s*4 .. s*4+3].
    outBits[s * 4 + 0] = (val >> 3) & 1;
    outBits[s * 4 + 1] = (val >> 2) & 1;
    outBits[s * 4 + 2] = (val >> 1) & 1;
    outBits[s * 4 + 3] = val & 1;
  }
  return new Map([["state", bitsToFipsBytes(outBits)]]);
};

export const desSBoxesDoc: StepDocumentation = {
  name: "S-boxes (S1..S8)",
  summary: "8 parallel 6→4 substitution boxes. The only nonlinear step in DES.",
  detail: `## S-boxes

The 48-bit input is split into eight 6-bit groups; each group is looked up
in its own 4 × 16 substitution table and produces a 4-bit output. The
eight outputs concatenate into the 32-bit result.

**Indexing each S-box.** For 6 input bits b1 b2 b3 b4 b5 b6:

\`\`\`
row  =  (b1 << 1) | b6              // outer bits, 0..3
col  =  (b2 << 3) | (b3 << 2)       // inner bits, 0..15
        | (b4 << 1) | b5
val  =  S_n[row][col]               // 4-bit output
\`\`\`

This is the cipher's **only nonlinear component**. Everything else (E, P,
IP, FP, the XOR with K) is linear over GF(2) and individually invertible
by another linear map. The S-boxes are what make DES a cipher rather than
an affine transform; replacing them with carefully chosen "weak" tables
(or even random ones) is a major topic in differential cryptanalysis.

Each of the 8 S-boxes is *distinct*. Unlike AES, which uses a single S-box
applied 16 times in parallel, DES uses 8 different tables so the
diffusion / confusion budget is spread across the input groups.`,
  params: new Map([
    [
      "sboxes",
      "8 substitution tables, each a 4×16 array of 4-bit values. DES_SBOXES in des-constants.ts.",
    ],
  ]),
  references: ["FIPS 46-3 Appendix A (Primitive functions for the data encryption algorithm)"],
  shapeContract: { input: "bytes", output: "bytes" },
};

// ─── Port contract (B4 — pure port-native, no projection meta) ──────────
// S-boxes collapse 6 bytes (48 bits) → 4 bytes (32 bits) — exact inverse
// of E's shape map. No aux. B4 dropped the projection meta (bytes arrive on
// the `state` port via portInputs). The S-box tables ride per-leaf as
// `params.sboxes` (the spec builder deep-copies them per leaf so editing
// one round doesn't bleed into siblings); the port shape is independent of
// the table values.

export const desSBoxesPortContract: PortContract = {
  // 6-byte input, 4-byte output — the second asymmetric state-port
  // declaration in the universal-port migration.
  inputs: new Map([["state", { byteLength: 6, layout: "raw" }]]),
  outputs: new Map([["state", { byteLength: 4, layout: "raw" }]]),
};

const readSBoxes = (params: Json): readonly (readonly (readonly number[])[])[] => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.s-boxes requires params.sboxes");
  }
  const p = params as { sboxes?: unknown };
  if (!Array.isArray(p.sboxes) || p.sboxes.length !== 8) {
    throw new Error("des.s-boxes: sboxes must be an 8-entry array");
  }
  for (let s = 0; s < 8; s++) {
    const box = p.sboxes[s];
    if (!Array.isArray(box) || box.length !== 4) {
      throw new Error(`des.s-boxes: S${s + 1} must be a 4-row array`);
    }
    for (let r = 0; r < 4; r++) {
      const row = box[r];
      if (!Array.isArray(row) || row.length !== 16) {
        throw new Error(`des.s-boxes: S${s + 1} row ${r} must be a 16-entry array`);
      }
    }
  }
  return p.sboxes as readonly (readonly (readonly number[])[])[];
};
