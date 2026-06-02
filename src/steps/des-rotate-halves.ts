/**
 * DES key-schedule half-rotation — port-native primitive
 * (key-schedule-decomposition slice K4a, 2026-06-02).
 *
 * Left-rotates the two `halfBits`-wide halves (C and D) of the DES key
 * register by `shift` bits each, independently. The 56-bit C ‖ D register
 * arrives as a 7-byte buffer on the `input` port (C = bits 1..28, D = bits
 * 29..56, FIPS MSB-first) and the rotated register leaves on `output`.
 *
 * **Verbatim lift of the monolith's loop body.** The retired
 * `des.key-schedule@1` did exactly this per round:
 *
 * ```
 * C = rotateBitsLeft(C, shift, 28);
 * D = rotateBitsLeft(D, shift, 28);
 * cdConcat = bitsToFipsBytes([...C, ...D]);
 * ```
 *
 * Reusing the same `fipsBytesToBits` / `rotateBitsLeft` / `bitsToFipsBytes`
 * helpers makes this byte-identical to the monolith by construction (the
 * same "lift, don't reconstruct" principle K3 used for `serpent.key-sbox@1`).
 *
 * **Why a dedicated step, not a build-generated bit-permute.** A left
 * rotation IS a fixed bit permutation, so it COULD be expressed as a
 * `des.bit-permute@1` with a 56-entry rotation table. A dedicated step was
 * chosen (K4 advisor pass, 2026-06-02) because the cycling C / D halves are
 * the *signature* feature of the DES schedule — its constants doc calls out
 * the cumulative-28 cycle (C₁₆ = C₀). `des.rotate-halves@1(shift: 2)` is
 * self-describing where a build-generated permute table buries "rotate" in
 * narration and shows a wall of indices in the editor.
 *
 * Port-native: `kind:"ported"`, one raw `input` port, one raw `output`
 * port, no `meta`, no `shapeContract`.
 */

import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { bitsToFipsBytes, fipsBytesToBits, rotateBitsLeft } from "./des-bit-ops";

type Params = {
  readonly shift: number;
  readonly halfBits: number;
};

const readParams = (params: Json): Params => {
  if (typeof params !== "object" || params === null || Array.isArray(params)) {
    throw new Error("des.rotate-halves: params must be an object");
  }
  const p = params as { shift?: unknown; halfBits?: unknown };
  if (typeof p.halfBits !== "number" || !Number.isInteger(p.halfBits) || p.halfBits < 1) {
    throw new Error("des.rotate-halves: params.halfBits must be a positive integer (DES uses 28)");
  }
  if (typeof p.shift !== "number" || !Number.isInteger(p.shift) || p.shift < 0) {
    throw new Error(
      "des.rotate-halves: params.shift must be a non-negative integer (DES uses 1 or 2)",
    );
  }
  return { shift: p.shift, halfBits: p.halfBits };
};

/**
 * Read the 2·halfBits-wide register off `input`, left-rotate each half by
 * `shift`, and re-emit. Allocates fresh; never mutates the input.
 */
export const desRotateHalves: PortedExecutor = (inputs, params, _ctx) => {
  const { shift, halfBits } = readParams(params);
  const input = inputs.get("input");
  const totalBits = 2 * halfBits;
  const expectedBytes = Math.ceil(totalBits / 8);
  if (!(input instanceof Uint8Array) || input.length !== expectedBytes) {
    throw new Error(
      `des.rotate-halves: input port 'input' must carry the ${expectedBytes}-byte (${totalBits}-bit) C‖D register; got ${
        input instanceof Uint8Array ? input.length : "non-bytes"
      }`,
    );
  }
  // C = bits 1..halfBits, D = bits halfBits+1..2·halfBits (FIPS MSB-first).
  const bits = fipsBytesToBits(input, totalBits);
  const c = rotateBitsLeft(bits.slice(0, halfBits), shift, halfBits);
  const d = rotateBitsLeft(bits.slice(halfBits, totalBits), shift, halfBits);
  return new Map([["output", bitsToFipsBytes([...c, ...d])]]);
};

// ─── Port contract ──────────────────────────────────────────────────────────
// Honest fixed declaration: DES's C‖D register is always 56 bits = 7 bytes.
// (`halfBits` is a param for clarity but DES never varies it from 28.)

export const desRotateHalvesPortContract: PortContract = {
  inputs: new Map([["input", { byteLength: 7, layout: "raw" }]]),
  outputs: new Map([["output", { byteLength: 7, layout: "raw" }]]),
};

export const desRotateHalvesDoc: StepDocumentation = {
  name: "Rotate C / D halves",
  summary: "Left-rotate the two 28-bit key halves (C and D) by `shift` bits each.",
  detail: `## Rotate C / D halves

The DES key register is two independent 28-bit halves, **C** and **D**,
packed into a 56-bit (7-byte) buffer — C = bits 1..28, D = bits 29..56,
FIPS MSB-first. Each round left-rotates **both** halves by the same
\`shift\` amount (1 or 2 bits, per the FIPS 46-3 shift schedule):

\`\`\`
C ← rotate-left(C, shift)
D ← rotate-left(D, shift)
\`\`\`

The two halves never mix here — the rotation is the only place the key
material moves between rounds. The shift amounts sum to **28** over the 16
rounds, so C₁₆ = C₀ and D₁₆ = D₀: the register cycles all the way around
and returns to its starting position. That is why the same 16 round keys
reappear (in reverse) when decrypting.

Each round's PC-2 then selects 48 bits of the freshly-rotated C ‖ D as
that round's key Kᵣ.`,
  params: new Map([
    [
      "shift",
      "Left-rotation amount in bits for this round (DES uses 1 or 2 per FIPS_46-3 SHIFTS).",
    ],
    ["halfBits", "Width of each half in bits. DES uses 28 (the register is 2 × 28 = 56 bits)."],
  ]),
  references: ["FIPS 46-3 §5 (Key Schedule — per-round left shifts of C and D)"],
  // No shapeContract — port-native (PortContract describes the surface).
};
