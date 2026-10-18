/**
 * ml-dsa.use-hint — recover the high bits the signer meant, from a value that
 * may have drifted one bucket (FIPS 204 Algorithm 40, `UseHint`).
 *
 * Four input ports: `h` (the hint, every coefficient 0 or 1), `r` (the
 * verifier's approximation, same length), `gamma2` (γ2) and `modulus` (q). One
 * output port `output`: the corrected high bits, each in `[0, m)` with
 * `m = (q − 1)/(2γ2)`.
 *
 * ## Which way to correct
 *
 * A hint of 1 says "this coefficient crossed a bucket edge" but not which edge.
 * The low part answers that: if `r0 > 0` the value sits in the upper half of its
 * bucket, so the edge it crossed was the upper one and the intended bucket is
 * `r1 + 1`; otherwise it is `r1 − 1`. Both wrap modulo `m`, because the buckets
 * sit on a circle — bucket 0's lower neighbour is bucket `m − 1`.
 *
 * FIPS 204 states the correctness property this relies on, and
 * `tests/ml-dsa-rounding.test.ts` checks it over every `r`:
 *
 * ```
 * UseHint(MakeHint(z, r), r) = HighBits(r + z)     whenever ‖z‖∞ ≤ γ2
 * ```
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import {
  checkGamma2,
  packNumbers,
  readMlDsaModulus,
  readResidues,
  useHint,
} from "../core/ml-dsa-arith";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { readScalarPort, readZqVecParams } from "../core/zq-vector";

const STEP = "ml-dsa.use-hint";

export const mlDsaUseHintPortContract: PortContract = {
  inputs: new Map([
    ["h", { layout: "raw" }],
    ["r", { layout: "raw" }],
    ["gamma2", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const mlDsaUseHint: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const q = readMlDsaModulus(inputs, p, STEP);
  const gamma2 = readScalarPort(inputs, "gamma2", STEP);
  checkGamma2(gamma2, q, STEP);
  const h = readResidues(inputs, "h", p, q, STEP);
  const r = readResidues(inputs, "r", p, q, STEP);
  if (h.length !== r.length) {
    throw new Error(
      `${STEP}: ports "h" (${h.length} coefficients) and "r" (${r.length}) must be the same length`,
    );
  }
  h.forEach((bit, i) => {
    if (bit > 1) {
      throw new Error(`${STEP}: hint coefficient ${i} is ${bit}; a hint is one bit, 0 or 1`);
    }
  });
  return new Map([
    [
      "output",
      packNumbers(
        h.map((bit, i) => useHint(bit, r[i] as number, gamma2, q)),
        p,
      ),
    ],
  ]);
};

export const mlDsaUseHintDoc: StepDocumentation = {
  name: "UseHint — correct the drifted high bits",
  summary:
    "Takes the verifier's approximate value and the signer's hint bit, and returns the high bits the signer actually committed to.",
  detail: `# UseHint

The verifier's half of the hint mechanism. For each coefficient it takes the
value it computed, \`r\`, and the signer's hint bit \`h\`:

- **\`h = 0\`** — no correction: return \`HighBits(r)\`.
- **\`h = 1\`** — the value drifted into a neighbouring bucket. Move one bucket
  back: **up** if \`r\` sits in the upper half of its bucket (\`r0 > 0\`), **down**
  otherwise.

\`\`\`
(r1, r0) = Decompose(r)
h = 1 and r0 > 0   →   (r1 + 1) mod m
h = 1 and r0 ≤ 0   →   (r1 − 1) mod m
h = 0              →   r1
\`\`\`

with \`m = (q − 1) / (2γ2)\`, the number of buckets — 44 at ML-DSA-44's
parameters.

## Why the direction can be read off the low bits

A small drift that crossed a bucket edge must have crossed the **nearer** edge.
If the value now sits in the upper half of its bucket, the edge it just came
through is the upper one, so the bucket it came from is the one above.

## Buckets on a circle

The correction wraps: one below bucket 0 is bucket 43, and one above bucket 43
is bucket 0. That is not a convenience — the values really do sit on a circle,
because \`q − 1\` and \`−1\` are the same number here.

## The guarantee

As long as the drift is no bigger than γ2, the corrected result is exactly the
high bits the signer saw. The signing loop's checks exist to make sure that
condition holds before a signature is ever released.`,
  params: new Map([
    ["coeffBytes", "How many bytes each coefficient occupies. 4 for ML-DSA."],
    [
      "littleEndian",
      "Byte order within one coefficient, for both inputs and the output. False (big-endian) matches every other wire in this app.",
    ],
  ]),
  references: [
    "FIPS 204 Algorithm 40 — UseHint",
    "FIPS 204 Algorithm 8 (ML-DSA.Verify_internal) — w′1 ← UseHint(h, w′approx) in verification",
  ],
};
