/**
 * zq-vec-sub — element-wise subtraction of two vectors over Z_q.
 *
 * Three input ports: `a`, `b` (the vectors, equal length) and `modulus` (q).
 * One output port `output`, the same length as the inputs, carrying
 * `(a[i] − b[i]) mod q` for every coefficient position `i`.
 *
 * ## There are no negative numbers here
 *
 * The single thing worth knowing about this step. In `Z_q` every value is an
 * integer in `[0, q)`, so a subtraction that would go below zero wraps back up
 * by adding `q` — `3 − 5 mod 3329 = 3327`, not `−2`. That is not a workaround
 * for a byte array's inability to hold a sign; it is what subtraction *means* in
 * this ring. A learner who reads 3327 as "a large number" rather than "−2" will
 * find the transform's output baffling, which is why the doc below leads with it.
 *
 * ## Where it fits
 *
 * The lower half of the Cooley–Tukey butterfly (FIPS 203 Algorithm 9):
 *
 * ```
 * t      = ζ · hi          (zq-vec-mul-scalar@1)
 * lo'    = lo + t          (zq-vec-add@1)
 * hi'    = lo − t          ← this step
 * ```
 *
 * and the Gentleman–Sande butterfly of the inverse transform, where the
 * subtraction comes first and the twiddle multiply second.
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`. Vector port lengths
 * are wiring-determined.
 */

import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import {
  readCoeff,
  readZqModulus,
  readZqVecParams,
  requireZqPort,
  writeCoeff,
  zqElementCount,
} from "../core/zq-vector";

const STEP = "zq-vec-sub";

export const zqVecSubPortContract: PortContract = {
  inputs: new Map([
    ["a", { layout: "raw" }],
    ["b", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const zqVecSub: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const a = requireZqPort(inputs, "a", STEP);
  const b = requireZqPort(inputs, "b", STEP);
  const q = readZqModulus(inputs.get("modulus"), p, STEP);
  const n = zqElementCount(a, p, "a", STEP);
  if (b.length !== a.length) {
    throw new Error(
      `${STEP}: ports "a" (${a.length} bytes) and "b" (${b.length} bytes) must be the same length — element-wise subtraction pairs coefficient i with coefficient i`,
    );
  }
  const out = new Uint8Array(a.length);
  for (let i = 0; i < n; i++) {
    // `+ q` before the reduction is what keeps the result in [0, q). The
    // operands are already reduced by construction in the NTT, but this step
    // must be correct for any wiring a user builds, so the lift is
    // unconditional: `((x mod q) + q) mod q` is non-negative for any x.
    const diff = ((readCoeff(a, i, p) - readCoeff(b, i, p)) % q) + q;
    writeCoeff(out, i, diff % q, p);
  }
  return new Map([["output", out]]);
};

export const zqVecSubDoc: StepDocumentation = {
  name: "Vector subtract mod q",
  summary:
    "Subtracts one list of numbers from another position by position; results that would go below zero wrap back up by q.",
  detail: `# Vector subtract mod q

Subtracts two equal-length lists of numbers position by position, keeping each
result in the range 0 up to (but not including) \`q\`.

## Math

\`\`\`
output[i] = (a[i] − b[i]) mod q
\`\`\`

## There are no negative numbers here

This is the one thing to know about this step, and it surprises everyone once.

Every value in this system is a whole number between 0 and \`q − 1\`. So a
subtraction that would land below zero does not produce a negative number — it
wraps back up:

\`\`\`
3 − 5  mod 3329  =  3327
\`\`\`

3327 **is** −2 here. They are the same element; there is no other way to write
it. This is not a trick to fit negative numbers into bytes — it is what
subtraction means when you are working on a clock face with 3329 positions.

If you read a large value in the output and it seems out of place, try
subtracting \`q\` from it in your head. A result of 3327 is a small negative
number wearing a large positive disguise.

## Where it fits

- **The butterfly.** The other half of the transform's two-line core: one line
  adds the twisted value, this one subtracts it. The pair is what makes the
  transform invertible.
- **Polynomial subtraction.** Wherever one polynomial in the ring is subtracted
  from another.`,
  params: new Map([
    [
      "coeffBytes",
      "How many bytes each coefficient occupies. 2 here — enough to hold any value below 3329.",
    ],
    [
      "littleEndian",
      "Byte order within one coefficient. False (big-endian, most significant byte first) matches how every other value in this app travels a wire.",
    ],
  ]),
  references: [
    "FIPS 203 §2.4.4 — the ring R_q = Z_q[X]/(X^256+1)",
    "FIPS 203 Algorithm 9 / Algorithm 10 — the forward and inverse butterflies",
  ],
};
