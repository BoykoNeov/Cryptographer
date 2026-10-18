/**
 * ml-dsa.decompose — split every coefficient into a bucket index and an offset
 * within that bucket (FIPS 204 Algorithm 36, `Decompose`; Algorithms 37–38,
 * `HighBits` and `LowBits`, are its two outputs).
 *
 * Three input ports: `a` (the vector), `gamma2` (γ2, big-endian, any width) and
 * `modulus` (q). Two output ports, each the same length as `a`:
 *
 * - `high` — `r1 = HighBits(r)`, which of the `2γ2`-wide buckets `r` falls in;
 * - `low` — `r0 = LowBits(r)`, the centred offset in `(−γ2, γ2]`, carried as
 *   `r0 mod q`.
 *
 * ## Power2Round's sibling, with buckets that do not divide a power of two
 *
 * Same idea as `ml-dsa.power2round@1` — round to the nearest multiple, keep
 * what the rounding moved — but the multiple is `2γ2 = 190464` (ML-DSA-44)
 * rather than a power of two. `2γ2` divides `q − 1` exactly, into `m = 44`
 * buckets; the step throws if a learner's γ2 breaks that, because the special
 * case below depends on it.
 *
 * ## The special case, and why it exists
 *
 * The buckets tile `[0, q − 1)`. The values within γ2 of `q − 1` would round UP
 * to `q − 1` — but `q − 1 ≡ −1`, which is "just below zero", so they belong in
 * bucket 0 with a slightly negative offset. FIPS checks for exactly that
 * (`r⁺ − r0 = q − 1`) and sets `r1 = 0, r0 = r0 − 1`; the `− 1` keeps
 * `r1·2γ2 + r0 ≡ r` true. Without it `HighBits` returns 44 for those values,
 * one past the last real bucket. `tests/ml-dsa-rounding.test.ts` is exhaustive
 * over all `q` values, so the case is pinned at every point it fires.
 *
 * ## What it is for
 *
 * A signature commits to `w1 = HighBits(w)` — the high bits only. That is what
 * makes ML-DSA signatures short: the low bits are noise the verifier does not
 * need. The low bits are checked too (`‖r0‖∞ < γ2 − β`), because a candidate
 * whose low part sits near a bucket edge could flip buckets when the verifier
 * recomputes `w` slightly differently.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import {
  checkGamma2,
  decompose,
  packNumbers,
  readMlDsaModulus,
  readResidues,
  toResidue,
} from "../core/ml-dsa-arith";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { readScalarPort, readZqVecParams } from "../core/zq-vector";

const STEP = "ml-dsa.decompose";

export const mlDsaDecomposePortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["gamma2", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([
    ["high", { layout: "raw" }],
    ["low", { layout: "raw" }],
  ]),
};

export const mlDsaDecompose: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const q = readMlDsaModulus(inputs, p, STEP);
  const gamma2 = readScalarPort(inputs, "gamma2", STEP);
  checkGamma2(gamma2, q, STEP);
  const values = readResidues(inputs, "a", p, q, STEP);

  const high: number[] = [];
  const low: number[] = [];
  for (const r of values) {
    const { r1, r0 } = decompose(r, gamma2, q);
    high.push(r1);
    low.push(toResidue(r0, q));
  }
  return new Map([
    ["high", packNumbers(high, p)],
    ["low", packNumbers(low, p)],
  ]);
};

export const mlDsaDecomposeDoc: StepDocumentation = {
  name: "Decompose — high bits and low bits",
  summary:
    "Cuts the range 0…q−1 into buckets 2γ2 wide and reports, for each coefficient, which bucket it is in and how far from the bucket's centre.",
  detail: `# Decompose

Rounds each coefficient \`r\` to the nearest multiple of \`2γ2\` and reports both
halves of the result:

\`\`\`
r  ≡  r1 · 2γ2  +  r0        with  −γ2 < r0 ≤ γ2
\`\`\`

- \`r1\` — the **high bits**: which bucket \`r\` landed in.
- \`r0\` — the **low bits**: how far \`r\` sits from that bucket's centre.

At ML-DSA-44's parameters \`2γ2 = 190464\`, and the range 0 … \`q − 1\` divides into
exactly **44** buckets, numbered 0 to 43.

## The top of the range wraps round to zero

The values just below \`q\` are, on the clock face this arithmetic lives on,
just below **zero**. Rounding them up to \`q − 1\` would put them in a 45th
bucket that does not exist. So they are put in bucket 0 instead, with a
slightly negative offset — and the offset is nudged down by one more so that
\`r1 · 2γ2 + r0\` still lands back on \`r\`.

That one special case is easy to leave out, and the result is wrong only for
the top sliver of values, which is exactly the kind of error a few spot checks
miss.

## Why a signature only keeps the high bits

A signer commits to \`w1\`, the high bits of a vector \`w\`. The verifier
recomputes \`w\` slightly differently — off by a small amount — and only needs the
high bits to come out the same. Dropping the low bits is what keeps an ML-DSA
signature small.

The low bits still get checked: if a coefficient sits too close to a bucket
edge, the verifier's small error could push it across. A candidate signature
with \`‖r0‖∞ ≥ γ2 − β\` is thrown away for that reason.

## γ2 is wired, not set here

γ2 arrives on a port so that one constant can drive this step, the two hint
steps and the bound checks together. It must divide \`(q − 1) / 2\`; the step
refuses any γ2 that does not, because the wrap-round fix above assumes a whole
number of buckets.`,
  params: new Map([
    ["coeffBytes", "How many bytes each coefficient occupies. 4 for ML-DSA."],
    [
      "littleEndian",
      "Byte order within one coefficient, for the input and both outputs. False (big-endian) matches every other wire in this app.",
    ],
  ]),
  references: [
    "FIPS 204 Algorithm 36 — Decompose",
    "FIPS 204 Algorithms 37 and 38 — HighBits and LowBits",
  ],
};
