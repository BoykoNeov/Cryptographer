/**
 * ml-dsa.expand-mask — the signer's masking vector y for one attempt, every
 * coefficient in `(−γ1, γ1]` (FIPS 204 Algorithm 34, `ExpandMask`).
 *
 * Four input ports: `input` (the 64-byte seed ρ″), `kappa` (κ, the attempt's
 * counter, big-endian), `gamma1` (γ1, big-endian) and `modulus` (q). One output
 * port `output`: l polynomials.
 *
 * ## What y is for, and why it changes every attempt
 *
 * The signature's response is `z = y + c·s1`. The mask y is what hides s1: it
 * is large and uniform, so `z` reveals nothing about the small secret added to
 * it — PROVIDED the candidate is kept only when `z` stays inside a safe range
 * (`‖z‖∞ < γ1 − β`). When a candidate is thrown away, the next attempt needs a
 * fresh y, and κ is what makes it fresh: attempt `n` uses κ = n·l, so its l
 * polynomials draw from counters κ, κ+1, …, κ+l−1 and never repeat one.
 *
 * ## No rejection here
 *
 * Unlike the other samplers, this one keeps every value. Each polynomial is
 * exactly `32·c` bytes of SHAKE256, where `c = 1 + bitlen(γ1 − 1)` — 18 bits a
 * coefficient for γ1 = 2¹⁷ — unpacked as `γ1 − x` for each c-bit chunk x. Since
 * γ1 is a power of two, every chunk lands in range.
 *
 * ## Why κ and γ1 are on ports
 *
 * κ changes from attempt to attempt, so it has to arrive with the data. γ1 is
 * the number P4's signing experiment edits; on a port, one constant drives this
 * step, the bound `γ1 − β`, and the packing of z, so editing it cannot leave
 * them disagreeing.
 *
 * ## Byte orders, three of them
 *
 * κ arrives BIG-endian (this app's port convention), is appended to the seed as
 * two bytes LITTLE-endian (FIPS 204's `IntegerToBytes`), and the output is
 * unpacked least-significant-bit first (FIPS 204's `BitUnpack`). Each is fixed;
 * none is the `littleEndian` param, which describes only the outgoing
 * coefficients.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import { shake256 } from "../ciphers/keccak-compute";
import { bitlen } from "../core/ml-dsa-arith";
import type { Json, PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  readScalarPort,
  readZqBitWidth,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  writeCoeff,
} from "../core/zq-vector";

const STEP = "ml-dsa.expand-mask";
const N = 256;

export const mlDsaExpandMaskPortContract: PortContract = {
  inputs: new Map([
    ["input", { layout: "raw" }],
    ["kappa", { layout: "raw" }],
    ["gamma1", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: (params: Json) => {
    const { coeffBytes } = readZqVecParams(params, STEP);
    const l = readZqBitWidth(params, STEP, "l", 16);
    return new Map([["output", { layout: "raw" as const, byteLength: l * N * coeffBytes }]]);
  },
};

export const mlDsaExpandMask: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const l = readZqBitWidth(params, STEP, "l", 16);
  const seed = requireZqPort(inputs, "input", STEP);
  const kappa = readScalarPort(inputs, "kappa", STEP);
  const gamma1 = readScalarPort(inputs, "gamma1", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);
  if (gamma1 < 2) throw new Error(`${STEP}: γ1 must be at least 2, got ${gamma1}`);
  if (kappa + l - 1 > 0xffff) {
    throw new Error(
      `${STEP}: counter κ + l − 1 = ${kappa + l - 1} does not fit the two bytes FIPS 204 gives it`,
    );
  }
  const c = 1 + bitlen(gamma1 - 1);

  const out = new Uint8Array(l * N * p.coeffBytes);
  for (let r = 0; r < l; r++) {
    const counter = kappa + r;
    const input = new Uint8Array(seed.length + 2);
    input.set(seed);
    input[seed.length] = counter & 0xff;
    input[seed.length + 1] = (counter >> 8) & 0xff;
    const v = shake256(input, 32 * c);
    for (let i = 0; i < N; i++) {
      // BitUnpack(v, γ1 − 1, γ1): chunk i is bits i·c … i·c + c − 1, LSB first.
      let x = 0;
      for (let j = 0; j < c; j++) {
        const bit = i * c + j;
        if ((((v[bit >> 3] as number) >> (bit & 7)) & 1) === 1) x += 2 ** j;
      }
      const y = BigInt(gamma1 - x);
      writeCoeff(out, r * N + i, ((y % q) + q) % q, p);
    }
  }
  return new Map([["output", out]]);
};

export const mlDsaExpandMaskDoc: StepDocumentation = {
  name: "ExpandMask — this attempt's masking vector",
  summary:
    "Expands a seed and an attempt counter into the large random vector y that hides the secret key inside a signature.",
  detail: `# ExpandMask

Produces the **mask** y for one signing attempt: l polynomials whose
coefficients are spread evenly over \`−γ1 + 1 … γ1\` — about ±131,072 for
ML-DSA-44.

## What the mask is for

A signature contains \`z = y + c·s1\`, where s1 is the secret key and c a small
challenge. On its own \`c·s1\` would give the key away. Adding a big random y
drowns it out — as long as \`z\` stays well inside the range y was drawn from,
so that its value says nothing about which s1 was added. That condition is
checked afterwards, and a candidate that breaks it is thrown away.

## A fresh mask every attempt

When a candidate is thrown away, the next attempt must use a different y —
reusing one would leak the key. The counter κ is what makes it different:
attempt n uses κ = n · l, and its l polynomials are drawn from the counters
κ, κ + 1, …, κ + l − 1. No two attempts ever share one.

## How each polynomial is drawn

SHAKE256 over the 64-byte seed and the counter (two bytes, least significant
first), squeezed to exactly \`32·c\` bytes with \`c = 1 + bitlen(γ1 − 1)\` — 18 for
ML-DSA-44. That is cut into 256 chunks of c bits each, low bit first, and each
chunk x becomes \`γ1 − x\`. Nothing is ever thrown away here.

## γ1 is wired, not set here

γ1 arrives on a port, so a single constant drives this step, the size check on
z, and the way z is packed into the signature. Change it and all three move
together.

## The same sponge as Hash → SHAKE256

This step's SHAKE256 is the one the traced **Hash → SHAKE256** entry walks,
collapsed to one frame per call.`,
  params: new Map([
    ["coeffBytes", "How many bytes each outgoing coefficient occupies. 4."],
    ["littleEndian", "Byte order within one outgoing coefficient. False (big-endian)."],
    ["l", "How many polynomials in y. 4 for ML-DSA-44 — the same l as s1 and z."],
  ]),
  references: [
    "FIPS 204 Algorithm 34 — ExpandMask",
    "FIPS 204 Algorithm 19 — BitUnpack",
    "FIPS 204 Algorithm 7 (ML-DSA.Sign_internal) — κ advances by l per attempt",
  ],
};
