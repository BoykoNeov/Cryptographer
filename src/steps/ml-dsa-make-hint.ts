/**
 * ml-dsa.make-hint — one bit per coefficient: does adding `z` to `r` move it
 * into a different bucket? (FIPS 204 Algorithm 39, `MakeHint`.)
 *
 * Four input ports: `z` and `r` (vectors, equal length), `gamma2` (γ2) and
 * `modulus` (q). One output port `output`, the same length, every coefficient
 * 0 or 1:
 *
 * ```
 * h[i] = 1  if  HighBits(r[i]) ≠ HighBits(r[i] + z[i]),  else 0
 * ```
 *
 * ## The idea: lossy on purpose, with a few bits of repair
 *
 * The public key lost `t0` to `ml-dsa.power2round@1`, so the verifier can only
 * compute `w − c·t0`-ish — the true commitment `w` shifted by a small amount it
 * does not know. Usually that shift leaves the high bits alone. Occasionally it
 * pushes a coefficient across a bucket edge, and then the verifier's high bits
 * are wrong by one bucket.
 *
 * The signer CAN see both values, so it records, per coefficient, whether that
 * happened. In signing this step is called as `MakeHint(−c·t0, w − c·s2 + c·t0)`
 * — `z` is the shift the verifier will suffer and `r` is what it will start
 * from. The verifier's `ml-dsa.use-hint@1` then undoes the drift.
 *
 * It is the sibling of ML-KEM's compress/decompress pair — lossy compression
 * done deliberately — but where ML-KEM simply tolerates its rounding error,
 * here a handful of bits repairs it exactly. At most ω = 80 coefficients out of
 * 1024 may need repair; more than that and the candidate signature is thrown
 * away (`ml-dsa.hint-count@1`).
 *
 * ## Authoring conventions
 *
 * Port-native: no `legacy`, no `meta`, no `shapeContract`.
 */

import {
  checkGamma2,
  makeHint,
  packNumbers,
  readMlDsaModulus,
  readResidues,
} from "../core/ml-dsa-arith";
import type { PortContract, PortedExecutor, StepDocumentation } from "../core/types";
import { readScalarPort, readZqVecParams } from "../core/zq-vector";

const STEP = "ml-dsa.make-hint";

export const mlDsaMakeHintPortContract: PortContract = {
  inputs: new Map([
    ["z", { layout: "raw" }],
    ["r", { layout: "raw" }],
    ["gamma2", { layout: "raw" }],
    ["modulus", { layout: "raw" }],
  ]),
  outputs: new Map([["output", { layout: "raw" }]]),
};

export const mlDsaMakeHint: PortedExecutor = (inputs, params, _ctx) => {
  const p = readZqVecParams(params, STEP);
  const q = readMlDsaModulus(inputs, p, STEP);
  const gamma2 = readScalarPort(inputs, "gamma2", STEP);
  checkGamma2(gamma2, q, STEP);
  const z = readResidues(inputs, "z", p, q, STEP);
  const r = readResidues(inputs, "r", p, q, STEP);
  if (z.length !== r.length) {
    throw new Error(
      `${STEP}: ports "z" (${z.length} coefficients) and "r" (${r.length}) must be the same length`,
    );
  }
  return new Map([
    [
      "output",
      packNumbers(
        z.map((zi, i) => makeHint(zi, r[i] as number, gamma2, q)),
        p,
      ),
    ],
  ]);
};

export const mlDsaMakeHintDoc: StepDocumentation = {
  name: "MakeHint — which coefficients will drift a bucket",
  summary:
    "For each coefficient, records one bit: does adding a small correction move it into a different high-bits bucket?",
  detail: `# MakeHint

Produces one bit per coefficient:

\`\`\`
h[i] = 1   if  HighBits(r[i] + z[i]) ≠ HighBits(r[i])
h[i] = 0   otherwise
\`\`\`

## Why a signature carries hints

To keep the public key small, the signer published only the high bits of part
of its key. A verifier working from that public key therefore computes the
signer's commitment **slightly wrong** — off by a small amount it cannot know.

Most of the time that small error changes nothing: the high bits come out the
same. But a coefficient sitting near a bucket edge can be nudged across it, and
then the verifier's high bits are off by one bucket.

The signer knows both the value and the nudge, so it can tell in advance which
coefficients will be nudged across. This step writes that down: a 1 for each
coefficient that will cross, a 0 for the rest. The verifier reads the bits back
and corrects exactly those coefficients — see UseHint.

## How many is allowed

Crossings are rare, so the hint is almost all zeros. ML-DSA-44 allows at most
**ω = 80** ones across all 1024 coefficients. A candidate signature needing more
is discarded and the signer tries again; it is one of the four checks in the
signing loop.

## A cousin of compression

This is lossy compression done on purpose, the same family of idea as ML-KEM's
compress / decompress pair. The difference is the repair: ML-KEM lives with its
rounding error, while here a few dozen bits make the result exact.`,
  params: new Map([
    ["coeffBytes", "How many bytes each coefficient occupies. 4 for ML-DSA."],
    [
      "littleEndian",
      "Byte order within one coefficient, for both inputs and the output. False (big-endian) matches every other wire in this app.",
    ],
  ]),
  references: [
    "FIPS 204 Algorithm 39 — MakeHint",
    "FIPS 204 Algorithm 7 (ML-DSA.Sign_internal) — h ← MakeHint(−c·t0, w − c·s2 + c·t0)",
  ],
};
