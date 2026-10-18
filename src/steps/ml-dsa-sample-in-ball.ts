/**
 * ml-dsa.sample-in-ball — the challenge polynomial c: exactly τ coefficients
 * are ±1, the rest 0 (FIPS 204 Algorithm 29, `SampleInBall`).
 *
 * Two input ports: `input` (the commitment hash c̃) and `modulus` (q, so −1 is
 * written `q − 1`). Two output ports:
 *
 * - `output` — the polynomial c, 256 coefficients;
 * - `rejections` — how many squeezed bytes were thrown away, two bytes
 *   big-endian.
 *
 * ## How it works: a shuffle
 *
 * The first 8 squeezed bytes are 64 sign bits. Then, for each position i from
 * `256 − τ` up to 255, one byte j is squeezed — rejected and re-squeezed while
 * `j > i` — and the step does `c[i] ← c[j]; c[j] ← ±1`. That is a Fisher–Yates
 * shuffle run only far enough to place τ nonzero entries: the result is a
 * uniformly random polynomial with exactly τ coefficients of ±1.
 *
 * ## Why `rejections` is a port
 *
 * Like ML-KEM's matrix sampler, the number of bytes this consumes depends on
 * the hash output, not on any size — a byte above i is discarded, and early on
 * (i near 217 for τ = 39) that is about one byte in seven. The count is
 * published so the narrator can show it rather than claim it.
 *
 * ## Why c has to be sparse
 *
 * c multiplies the secret vectors, and the result `c·s1` must be small for the
 * signature to be safe to release. With only τ = 39 nonzero coefficients each
 * ±1, every coefficient of `c·s1` is at most `τ·η = 78` = β in size. That is
 * exactly the β the signing checks subtract.
 *
 * ## The final standard reads all of c̃
 *
 * The round-3 draft hashed only the first 32 bytes of c̃; final FIPS 204 hashes
 * all `λ/4` of them. For ML-DSA-44 they are the same 32 bytes, so the
 * difference is invisible at this parameter set — and this step, which hashes
 * whatever arrives, is right for both.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { byteStream, shake256Reader } from "../ciphers/keccak-compute";
import { countBytes } from "../core/ml-dsa-arith";
import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  readZqBitWidth,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  writeCoeff,
} from "../core/zq-vector";

const STEP = "ml-dsa.sample-in-ball";
const N = 256;

export const mlDsaSampleInBallPortContract: PortContract = {
  inputs: new Map([
    ["input", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: (params: Json) => {
    const { coeffBytes } = readZqVecParams(params, STEP);
    return new Map([
      ["output", { layout: "raw" as const, byteLength: N * coeffBytes }],
      ["rejections", { layout: "raw" as const, byteLength: 2 }],
    ]);
  },
};

/**
 * The coefficients as signed numbers (−1, 0, 1), plus the rejection count.
 * Exported so the oracle test can call the sampler without a port round-trip.
 */
export const sampleInBall = (
  seed: Uint8Array,
  tau: number,
): { c: number[]; rejections: number } => {
  const stream = byteStream(shake256Reader(seed));
  const signs: number[] = [];
  for (let i = 0; i < 8; i++) signs.push(stream.next());
  const signBit = (k: number): number => ((signs[k >> 3] as number) >> (k & 7)) & 1;

  const c = new Array<number>(N).fill(0);
  let rejections = 0;
  for (let i = N - tau; i < N; i++) {
    let j = stream.next();
    while (j > i) {
      rejections += 1;
      j = stream.next();
    }
    c[i] = c[j] as number;
    c[j] = signBit(i + tau - N) === 1 ? -1 : 1;
  }
  return { c, rejections };
};

export const mlDsaSampleInBall: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  // τ ≤ 64: there are only 64 sign bits.
  const tau = readZqBitWidth(params, STEP, "tau", 64);
  const seed = requireZqPort(inputs, "input", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);
  const { c, rejections } = sampleInBall(seed, tau);
  const out = new Uint8Array(N * p.coeffBytes);
  c.forEach((v, i) => writeCoeff(out, i, ((BigInt(v) % q) + q) % q, p));
  return new Map([
    ["output", out],
    ["rejections", countBytes(rejections)],
  ]);
};

export const mlDsaSampleInBallDoc: StepDocumentation = {
  name: "SampleInBall — the challenge polynomial",
  summary:
    "Turns a 32-byte hash into a polynomial with exactly τ coefficients equal to +1 or −1 and every other coefficient zero.",
  detail: `# SampleInBall

Builds the **challenge** c from the commitment hash c̃: a polynomial with exactly
τ coefficients that are +1 or −1, and the other 256 − τ all zero. For ML-DSA-44,
τ = 39.

## Why the challenge is so sparse

The signature contains \`z = y + c·s1\`, and it is only safe to release if
\`c·s1\` is small. With 39 entries of ±1 and every secret coefficient at most
η = 2, no coefficient of \`c·s1\` can exceed 39 × 2 = **78**. That number has a
name, β, and the signing checks subtract it from their bounds to leave room for
exactly this.

## How it is drawn: a partial shuffle

SHAKE256 is squeezed over c̃. The first 8 bytes are 64 sign bits. Then, for
each position i from 256 − τ to 255:

1. squeeze one byte j, and squeeze again while j > i;
2. move whatever is at position j to position i;
3. put +1 or −1 (the next sign bit) at position j.

That is the classic Fisher–Yates shuffle, stopped after τ steps. It places the
nonzero entries uniformly at random.

## Its cost depends on the hash

A byte larger than i is thrown away and another squeezed, and how many that
happens to is a property of this particular hash output. The step publishes the
number on its \`rejections\` port.

## The same sponge as Hash → SHAKE256

This step's SHAKE256 is the one the traced **Hash → SHAKE256** entry walks,
collapsed to one frame.`,
  params: new Map([
    ["coeffBytes", "How many bytes each outgoing coefficient occupies. 4."],
    ["littleEndian", "Byte order within one outgoing coefficient. False (big-endian)."],
    ["tau", "How many coefficients are ±1. 39 for ML-DSA-44; at most 64, the number of sign bits."],
  ]),
  references: [
    "FIPS 204 Algorithm 29 — SampleInBall",
    "FIPS 204 Table 1 — τ = 39, β = τ·η = 78 for ML-DSA-44",
  ],
};
