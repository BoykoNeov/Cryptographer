/**
 * ml-dsa.power2round — split every coefficient into a high part and its low
 * `d` bits (FIPS 204 Algorithm 35, `Power2Round`).
 *
 * Two input ports: `a` (the vector) and `modulus` (q). Two output ports, each
 * the same length as `a`:
 *
 * - `high` — `r1`, the coefficient with its low `d` bits rounded away;
 * - `low` — `r0`, those low bits as a CENTRED value in `(−2^(d−1), 2^(d−1)]`,
 *   carried on the wire as `r0 mod q` (so −5 travels as `q − 5`).
 *
 * `r ≡ r1 · 2^d + r0 (mod q)` always holds — nothing is lost, it is only split.
 *
 * ## What it is for
 *
 * Key generation computes `t = A·s1 + s2`, a vector of 23-bit coefficients, and
 * applies this with `d = 13`. The high part `t1` (10 bits a coefficient) is the
 * public key; the low part `t0` is kept in the private key. That is why an
 * ML-DSA-44 public key is 1312 bytes and not 2976: thirteen of every twenty-three
 * bits never leave the signer.
 *
 * The verifier therefore works with `t1 · 2^d`, which is off from `t` by `t0` —
 * and the signer has to compensate. That compensation is the hint (see
 * `ml-dsa.make-hint@1`), and the reason `‖c·t0‖∞ < γ2` is one of the four
 * signing checks.
 *
 * ## Rounding to nearest, not truncating
 *
 * `r0` is centred, so `r1` is `r` rounded to the NEAREST multiple of `2^d`
 * (ties down), not `r` with its low bits chopped off. A truncating version is
 * self-consistent and yields a public key that matches nobody's.
 *
 * ## `d` is a param
 *
 * Unlike the bounds in this family, `d` is a structural size: it fixes the
 * public-key format (10 bits a coefficient) and the private key's `t0` width.
 * It is not one of the numbers the signing experiment edits.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import {
  packNumbers,
  power2Round,
  readMlDsaModulus,
  readResidues,
  toResidue,
} from "../core/ml-dsa-arith";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { readZqBitWidth, readZqVecParams } from "../core/zq-vector";

const STEP = "ml-dsa.power2round";

export const mlDsaPower2RoundPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([
    ["high", { layout: "raw" }],
    ["low", { layout: "raw" }],
  ]),
};

export const mlDsaPower2Round: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  // One bit short of the coefficient width, so `2^d` itself always fits.
  const d = readZqBitWidth(params, STEP, "d", 8 * p.coeffBytes - 1);
  const q = readMlDsaModulus(inputs, p, STEP);
  const values = readResidues(inputs, "a", p, q, STEP);

  const high: number[] = [];
  const low: number[] = [];
  for (const r of values) {
    const { r1, r0 } = power2Round(r, d, q);
    high.push(r1);
    low.push(toResidue(r0, q));
  }
  return new Map([
    ["high", packNumbers(high, p)],
    ["low", packNumbers(low, p)],
  ]);
};

export const mlDsaPower2RoundDoc: StepDocumentation = {
  name: "Power2Round — split off the low d bits",
  summary:
    "Splits each coefficient into a high part (published) and its low d bits (kept secret), rounding to the nearest multiple of 2^d.",
  detail: `# Power2Round

Splits each coefficient \`r\` into two pieces:

\`\`\`
r  ≡  r1 · 2^d  +  r0        with  −2^(d−1) < r0 ≤ 2^(d−1)
\`\`\`

\`r1\` is \`r\` rounded to the nearest multiple of \`2^d\`, divided by \`2^d\`. \`r0\` is
what the rounding moved it by — a small number that can be negative. Nothing is
thrown away; the value is only cut in two.

## Why a key is cut in two

Key generation produces a vector \`t\` whose coefficients are 23 bits each. With
\`d = 13\`, this step keeps the top 10 bits as \`t1\` — **that is the public key** —
and the bottom 13 as \`t0\`, which stays in the private key.

The payoff is size: the public key shrinks from 2976 bytes to 1312. The cost is
that anyone verifying a signature now knows \`t\` only roughly, to within \`t0\`.
The signer has to make up the difference, which is what the hint in a signature
is for.

## Rounding, not chopping

Because \`r0\` is centred on zero, this rounds to the *nearest* multiple —
\`r = 4097\` with \`d = 12\` becomes \`r1 = 1, r0 = 1\`, but \`r = 6143\` becomes
\`r1 = 1, r0 = 2047\` and \`r = 6145\` becomes \`r1 = 2, r0 = −2047\`. Simply chopping
off the low bits would give a consistent-looking public key that no other
implementation would recognise.

## Negative values on a wire

\`r0\` can be negative, and every coefficient on a wire is between 0 and
\`q − 1\`. So a negative \`r0\` travels the way every negative number does here:
−5 is written as \`q − 5\`.`,
  params: new Map([
    ["coeffBytes", "How many bytes each coefficient occupies. 4 for ML-DSA."],
    [
      "littleEndian",
      "Byte order within one coefficient, for the input and both outputs. False (big-endian) matches every other wire in this app.",
    ],
    [
      "d",
      "How many low bits to split off. 13 in every ML-DSA parameter set, which leaves 10 bits a coefficient for the public key.",
    ],
  ]),
  references: [
    "FIPS 204 Algorithm 35 — Power2Round",
    "FIPS 204 Algorithm 6 (ML-DSA.KeyGen_internal) — (t1, t0) ← Power2Round(t) in key generation",
  ],
};
