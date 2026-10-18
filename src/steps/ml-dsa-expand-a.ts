/**
 * ml-dsa.expand-a — expand the 32-byte public seed ρ into the whole k × l
 * matrix Â, already in the transformed domain (FIPS 204 Algorithm 32,
 * `ExpandA`, over Algorithm 30, `RejNTTPoly`).
 *
 * Two input ports: `input` (ρ) and `modulus` (q). One output port `output`:
 * the k·l polynomials in ROW-MAJOR order — `Â[0][0], Â[0][1], …, Â[k−1][l−1]`
 * — each 256 coefficients.
 *
 * ## The whole matrix in one step, and why that differs from ML-KEM
 *
 * ML-KEM samples one matrix entry per step and appends the two index bytes
 * OUTSIDE it, on the canvas, because its key generation and encryption append
 * them in opposite orders — that swap IS the transpose, and a load-bearing fact
 * belongs where a learner can see it.
 *
 * ML-DSA has no transpose. Key generation, signing and verification all use
 * `ExpandA(ρ)` the same way, so the index order is a single fixed convention
 * rather than a distinction between two call sites. That is what makes one
 * whole-matrix step honest here, and it saves sixteen joins per call. It is a
 * deliberate departure from the ML-KEM precedent, recorded in the plan's P2
 * outcome.
 *
 * **The convention, and it is easy to get backwards:** entry `Â[r][s]` is
 * drawn from `ρ ‖ s ‖ r` — the COLUMN index first, then the row — each one
 * byte. Swapping them builds the transpose, which still produces a perfectly
 * self-consistent key pair whose public key matches no other implementation.
 * `tests/ml-dsa-44-oracle.test.ts` pins the order against Node's real keys,
 * and perturbs it to show the failure.
 *
 * ## The rejection loop
 *
 * `RejNTTPoly` reads the SHAKE128 stream three bytes at a time, masks the top
 * bit to make a 23-bit candidate, and keeps it only if it is below q. About one
 * candidate in 1,024 is rejected, so a polynomial usually costs a little over
 * 768 bytes — but not always the same number, which is why the loop condition
 * is the accepted count and never a byte budget.
 *
 * ## Why the output is already transformed
 *
 * Nothing transforms anything: the bytes are declared to be NTT-domain values.
 * That is legitimate because Â is uniformly random and the transform is a
 * bijection — exactly the ML-KEM argument. The matrix is never needed in any
 * other form.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { byteStream, shake128Reader } from "../ciphers/keccak-compute";
import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  readZqBitWidth,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  writeCoeff,
} from "../core/zq-vector";

const STEP = "ml-dsa.expand-a";
const N = 256;

/** k and l: the matrix shape. Small positive integers; 16 is far past any parameter set. */
const readShape = (params: Json): { k: number; l: number } => ({
  k: readZqBitWidth(params, STEP, "k", 16),
  l: readZqBitWidth(params, STEP, "l", 16),
});

export const mlDsaExpandAPortContract: PortContract = {
  inputs: new Map([
    ["input", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: (params: Json) => {
    const { coeffBytes } = readZqVecParams(params, STEP);
    const { k, l } = readShape(params);
    return new Map([["output", { layout: "raw" as const, byteLength: k * l * N * coeffBytes }]]);
  },
};

/**
 * `RejNTTPoly(seed)` — 256 accepted coefficients from the SHAKE128 stream.
 * Exported so `ml-dsa.expand-a@1` is not the only caller a test can reach.
 */
export const rejNttPoly = (seed: Uint8Array, q: number): number[] => {
  const stream = byteStream(shake128Reader(seed));
  const out: number[] = [];
  while (out.length < N) {
    const b0 = stream.next();
    const b1 = stream.next();
    const b2 = stream.next();
    // CoeffFromThreeBytes (Algorithm 14): little-endian, top bit of b2 masked.
    const c = b0 + 256 * b1 + 65536 * (b2 & 0x7f);
    if (c < q) out.push(c);
  }
  return out;
};

export const mlDsaExpandA: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const { k, l } = readShape(params);
  const rho = requireZqPort(inputs, "input", STEP);
  const q = Number(readZqModulus(inputs.get("modulus"), p, STEP));

  const out = new Uint8Array(k * l * N * p.coeffBytes);
  for (let r = 0; r < k; r++) {
    for (let s = 0; s < l; s++) {
      // ρ ‖ s ‖ r — column first. See the header: this order is the transpose's
      // whole difference, and it is pinned against real keys.
      const seed = new Uint8Array(rho.length + 2);
      seed.set(rho);
      seed[rho.length] = s;
      seed[rho.length + 1] = r;
      const poly = rejNttPoly(seed, q);
      const base = (r * l + s) * N;
      poly.forEach((c, i) => writeCoeff(out, base + i, BigInt(c), p));
    }
  }
  return new Map([["output", out]]);
};

export const mlDsaExpandADoc: StepDocumentation = {
  name: "ExpandA — the public matrix from a seed",
  summary:
    "Expands a 32-byte seed into the whole k × l matrix of uniformly random polynomials, by squeezing SHAKE128 and keeping only candidates below q.",
  detail: `# ExpandA

Turns the 32-byte public seed ρ into the matrix **Â**: k rows by l columns of
polynomials, every coefficient uniformly random below q. For ML-DSA-44 that is
4 × 4 = 16 polynomials, 4,096 coefficients.

## How each entry is drawn

Entry \`Â[r][s]\` gets its own seed, ρ followed by two index bytes, and that seed
is squeezed through **SHAKE128**. The output is read three bytes at a time:

\`\`\`
c = b₀ + 256·b₁ + 65536·(b₂ mod 128)        a 23-bit candidate
keep it if c < q,  otherwise throw it away
\`\`\`

The top bit of the third byte is dropped first, so the candidates run to
2²³ − 1 = 8,388,607 — only slightly above q = 8,380,417. About one candidate in
1,024 is discarded, so most entries cost just over 768 bytes of squeezing, but
the exact amount depends on the hash output and cannot be known in advance.

## Column first, then row

The two index bytes are the column \`s\` and then the row \`r\`, in that order.
Swap them and you build the **transpose** — a key pair that works perfectly
with itself and matches no other implementation in the world.

ML-KEM attaches its index bytes on the canvas, outside its sampling step,
because it needs both orders in different places. ML-DSA only ever builds the
matrix one way, so here the order lives inside this step and the whole matrix
comes out at once.

## Already transformed

The coefficients are simply declared to be in the transformed (NTT) domain.
That is allowed because the matrix only has to be uniformly random, and a
random value is just as random after a one-to-one relabelling. It saves
sixteen transforms, and the matrix is never wanted in any other form.

## The same sponge as Hash → SHAKE128

This step's SHAKE128 drives the same step executors the traced **Hash →
SHAKE128** entry walks, collapsed to one frame. Squeezing sixteen polynomials
in full would bury the lattice arithmetic under thousands of Keccak frames.`,
  params: new Map([
    ["coeffBytes", "How many bytes each sampled coefficient occupies on the way out. 4."],
    ["littleEndian", "Byte order within one outgoing coefficient. False (big-endian)."],
    ["k", "Rows of the matrix. 4 for ML-DSA-44."],
    ["l", "Columns of the matrix. 4 for ML-DSA-44."],
  ]),
  references: [
    "FIPS 204 Algorithm 32 — ExpandA",
    "FIPS 204 Algorithm 30 — RejNTTPoly",
    "FIPS 204 Algorithm 14 — CoeffFromThreeBytes",
    "FIPS 202 §6.2 — SHAKE128",
  ],
};
