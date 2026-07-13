/**
 * keccak.theta — the θ (theta) step of Keccak-f[1600] (SHA-3, FIPS 202
 * §3.2.1), 2026-07-13.
 *
 * **Why this is one step, not a decomposition.** θ mixes the five lanes of
 * each *column* together, and the columns of Keccak's state are **not
 * contiguous** in the byte string: lane `(x,y)` lives at bytes
 * `[8·(x+5y) .. +8)`, so a single column `x` is the five lanes at slots
 * `x, x+5, x+10, x+15, x+20`. Decomposing θ into universal primitives would
 * need ~30 leaves of non-contiguous lane extraction, XOR, a rotate-by-1, and
 * a broadcast-XOR back — a wall with no pedagogical payoff. Encapsulating it
 * as one leaf (with a rich narrator, the Twofish h-expand precedent) keeps the
 * five named Keccak steps θ→ρ→π→χ→ι reading as five leaves per round.
 *
 * **What θ does (FIPS 202 §3.2.1).** For the 5×5 grid of 64-bit lanes,
 * little-endian:
 *
 * ```
 * C[x]      = A[x,0] ⊕ A[x,1] ⊕ A[x,2] ⊕ A[x,3] ⊕ A[x,4]        (column parity)
 * D[x]      = C[(x−1) mod 5] ⊕ ROTL(C[(x+1) mod 5], 1)          (mix neighbours)
 * A'[x,y]   = A[x,y] ⊕ D[x]                                     (fold into every lane)
 * ```
 *
 * θ is the state's principal source of **diffusion**: each output bit depends
 * on 11 input bits (its own lane plus two whole neighbouring columns), so a
 * one-bit input change propagates widely after just a few rounds.
 *
 * **Fixed geometry (v1).** Keccak-f[1600]: 25 lanes of 64 bits = 200 bytes,
 * little-endian. No params — the geometry is fixed. (A future Keccak-p variant
 * with a different lane width would be a separate step type or add a param.)
 *
 * **Authoring conventions.** Port-native: `kind:"ported"`, omit `legacy`,
 * `meta`, `shapeContract`. One `input` port and one `output` port, both the
 * 200-byte state.
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";

// ─── Keccak-f[1600] geometry ────────────────────────────────────────────────

const LANES = 25; // 5×5
const LANE_BYTES = 8; // 64-bit lanes
const STATE_BYTES = LANES * LANE_BYTES; // 200
const MASK64 = (1n << 64n) - 1n;

/** Byte offset of lane (x,y) in the little-endian state string. */
const laneStart = (x: number, y: number): number => (x + 5 * y) * LANE_BYTES;

/** Decode the little-endian 64-bit lane at byte offset `start`. */
const getLane = (s: Uint8Array, start: number): bigint => {
  let v = 0n;
  for (let b = 0; b < LANE_BYTES; b++) v |= BigInt(s[start + b] as number) << BigInt(8 * b);
  return v;
};

/** Encode `v` as a little-endian 64-bit lane at byte offset `start`. */
const putLane = (out: Uint8Array, start: number, v: bigint): void => {
  for (let b = 0; b < LANE_BYTES; b++) out[start + b] = Number((v >> BigInt(8 * b)) & 0xffn);
};

const rotl1 = (v: bigint): bigint => ((v << 1n) | (v >> 63n)) & MASK64;

// ─── Port contract + executor ─────────────────────────────────────────────

export const keccakThetaPortContract: PortContract = {
  inputs: new Map([["input", { layout: "raw", byteLength: STATE_BYTES }]]),
  outputs: new Map([["output", { layout: "raw", byteLength: STATE_BYTES }]]),
};

export const keccakTheta: PortedExecutor = (inputs, _params, _ctx) => {
  const s = inputs.get("input");
  if (s === undefined) {
    throw new Error("keccak.theta: missing required input port 'input'");
  }
  if (s.length !== STATE_BYTES) {
    throw new Error(
      `keccak.theta: input must be ${STATE_BYTES} bytes (Keccak-f[1600]), got ${s.length}`,
    );
  }
  // C[x] = XOR of the five lanes in column x.
  const C: bigint[] = new Array(5);
  for (let x = 0; x < 5; x++) {
    let c = 0n;
    for (let y = 0; y < 5; y++) c ^= getLane(s, laneStart(x, y));
    C[x] = c;
  }
  // D[x] = C[x−1] ⊕ ROTL(C[x+1], 1).
  const D: bigint[] = new Array(5);
  for (let x = 0; x < 5; x++) {
    D[x] = (C[(x + 4) % 5] as bigint) ^ rotl1(C[(x + 1) % 5] as bigint);
  }
  // A'[x,y] = A[x,y] ⊕ D[x].
  const out = new Uint8Array(STATE_BYTES);
  for (let x = 0; x < 5; x++) {
    for (let y = 0; y < 5; y++) {
      const start = laneStart(x, y);
      putLane(out, start, getLane(s, start) ^ (D[x] as bigint));
    }
  }
  return new Map([["output", out]]);
};

// ─── Doc ──────────────────────────────────────────────────────────────────

export const keccakThetaDoc: StepDocumentation = {
  name: "θ (theta)",
  summary:
    "Keccak's column-mixing step: XORs each lane with the parity of two neighbouring columns.",
  detail: `# θ (theta)

The first of Keccak-f's five steps (FIPS 202 §3.2.1). It views the 1600-bit
state as a 5×5 grid of 64-bit **lanes** and mixes whole **columns** together —
this is Keccak's main **diffusion** engine.

## Math

Little-endian lanes, indices mod 5:

\`\`\`
C[x]    = A[x,0] ⊕ A[x,1] ⊕ A[x,2] ⊕ A[x,3] ⊕ A[x,4]     (parity of column x)
D[x]    = C[x−1] ⊕ ROTL(C[x+1], 1)                       (a neighbour mix)
A'[x,y] = A[x,y] ⊕ D[x]                                   (folded into every lane)
\`\`\`

The one-bit left rotation inside \`D[x]\` is what couples columns across the
64-bit lane direction, so θ spreads changes in all three axes.

## Why it matters

After θ, every output bit depends on **11** input bits (its own lane plus two
entire neighbouring columns). That wide dependence, repeated over 24 rounds and
interleaved with ρ, π, χ and ι, is what gives Keccak its avalanche: flipping one
input bit flips about half the output bits.`,
  params: new Map(),
  references: ["FIPS 202 §3.2.1 (Keccak θ step)"],
  // No `shapeContract` — port-native steps describe their surface via
  // PortContract.
};
